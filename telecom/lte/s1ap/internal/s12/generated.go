// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s12 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s12

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// NASDeliveryIndicationIEContainer is ProtocolIE-Container {{NASDeliveryIndicationIEs}} of TS 36.413: a list of NASDeliveryIndicationIEField values.
type NASDeliveryIndicationIEContainer []NASDeliveryIndicationIEField

// NASDeliveryIndicationIEField is ProtocolIE-Field {{NASDeliveryIndicationIEs}} of TS 36.413: an information element field.
type NASDeliveryIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         NASDeliveryIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEField) WithoutReplay() NASDeliveryIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NASDeliveryIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NASDeliveryIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *NASDeliveryIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASDeliveryIndicationIEField{}
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
	var zero NASDeliveryIndicationIEValue

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

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MeasurementThresholdL1LoggedMDT-ExtIEs}} of TS 36.413: a single information element field.
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer = MeasurementThresholdL1LoggedMDTExtIEField

// MutingPatternInformationExtIEsExtContainer is ProtocolExtensionContainer {{MutingPatternInformation-ExtIEs}} of TS 36.413: a list of MutingPatternInformationExtIEsExtField values.
type MutingPatternInformationExtIEsExtContainer []MutingPatternInformationExtIEsExtField

// NBIoTPagingEDRXInformationExtIEsExtContainer is ProtocolExtensionContainer {{NB-IoT-Paging-eDRXInformation-ExtIEs}} of TS 36.413: a list of NBIoTPagingEDRXInformationExtIEsExtField values.
type NBIoTPagingEDRXInformationExtIEsExtContainer []NBIoTPagingEDRXInformationExtIEsExtField

// NRCGIExtIEsExtContainer is ProtocolExtensionContainer {{NR-CGI-ExtIEs}} of TS 36.413: a list of NRCGIExtIEsExtField values.
type NRCGIExtIEsExtContainer []NRCGIExtIEsExtField

// NRUESecurityCapabilitiesExtIEsExtContainer is ProtocolExtensionContainer {{NRUESecurityCapabilities-ExtIEs}} of TS 36.413: a list of NRUESecurityCapabilitiesExtIEsExtField values.
type NRUESecurityCapabilitiesExtIEsExtContainer []NRUESecurityCapabilitiesExtIEsExtField

// NRV2XServicesAuthorizedExtIEsExtContainer is ProtocolExtensionContainer {{NRV2XServicesAuthorized-ExtIEs}} of TS 36.413: a list of NRV2XServicesAuthorizedExtIEsExtField values.
type NRV2XServicesAuthorizedExtIEsExtContainer []NRV2XServicesAuthorizedExtIEsExtField

// NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer is ProtocolExtensionContainer {{NRUESidelinkAggregateMaximumBitrate-ExtIEs}} of TS 36.413: a list of NRUESidelinkAggregateMaximumBitrateExtIEsExtField values.
type NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer []NRUESidelinkAggregateMaximumBitrateExtIEsExtField

// PagingAttemptInformationExtIEsExtContainer is ProtocolExtensionContainer {{PagingAttemptInformation-ExtIEs}} of TS 36.413: a list of PagingAttemptInformationExtIEsExtField values.
type PagingAttemptInformationExtIEsExtContainer []PagingAttemptInformationExtIEsExtField

// PagingEDRXInformationExtIEsExtContainer is ProtocolExtensionContainer {{Paging-eDRXInformation-ExtIEs}} of TS 36.413: a list of PagingEDRXInformationExtIEsExtField values.
type PagingEDRXInformationExtIEsExtContainer []PagingEDRXInformationExtIEsExtField

// PC5QoSParametersExtIEsExtContainer is ProtocolExtensionContainer {{PC5QoSParameters-ExtIEs}} of TS 36.413: a list of PC5QoSParametersExtIEsExtField values.
type PC5QoSParametersExtIEsExtContainer []PC5QoSParametersExtIEsExtField

// PC5QoSFlowItemExtIEsExtContainer is ProtocolExtensionContainer {{PC5QoSFlowItem-ExtIEs}} of TS 36.413: a list of PC5QoSFlowItemExtIEsExtField values.
type PC5QoSFlowItemExtIEsExtContainer []PC5QoSFlowItemExtIEsExtField

// PC5FlowBitRatesExtIEsExtContainer is ProtocolExtensionContainer {{PC5FlowBitRates-ExtIEs}} of TS 36.413: a list of PC5FlowBitRatesExtIEsExtField values.
type PC5FlowBitRatesExtIEsExtContainer []PC5FlowBitRatesExtIEsExtField

// PLMNAreaBasedQMCExtIEsExtContainer is ProtocolExtensionContainer {{PLMNAreaBasedQMC-ExtIEs}} of TS 36.413: a list of PLMNAreaBasedQMCExtIEsExtField values.
type PLMNAreaBasedQMCExtIEsExtContainer []PLMNAreaBasedQMCExtIEsExtField

// ProSeAuthorizedExtIEsExtContainer is ProtocolExtensionContainer {{ProSeAuthorized-ExtIEs}} of TS 36.413: a list of ProSeAuthorizedExtIEsExtField values.
type ProSeAuthorizedExtIEsExtContainer []ProSeAuthorizedExtIEsExtField

// PSCellInformationExtIEsExtContainer is ProtocolExtensionContainer {{PSCellInformation-ExtIEs}} of TS 36.413: a list of PSCellInformationExtIEsExtField values.
type PSCellInformationExtIEsExtContainer []PSCellInformationExtIEsExtField

// RecommendedCellsForPagingExtIEsExtContainer is ProtocolExtensionContainer {{RecommendedCellsForPaging-ExtIEs}} of TS 36.413: a list of RecommendedCellsForPagingExtIEsExtField values.
type RecommendedCellsForPagingExtIEsExtContainer []RecommendedCellsForPagingExtIEsExtField

// RecommendedCellsForPagingItemExtIEsExtContainer is ProtocolExtensionContainer {{RecommendedCellsForPagingItem-ExtIEs}} of TS 36.413: a list of RecommendedCellsForPagingItemExtIEsExtField values.
type RecommendedCellsForPagingItemExtIEsExtContainer []RecommendedCellsForPagingItemExtIEsExtField

// RecommendedENBsForPagingExtIEsExtContainer is ProtocolExtensionContainer {{RecommendedENBsForPaging-ExtIEs}} of TS 36.413: a list of RecommendedENBsForPagingExtIEsExtField values.
type RecommendedENBsForPagingExtIEsExtContainer []RecommendedENBsForPagingExtIEsExtField

// RecommendedENBItemExtIEsExtContainer is ProtocolExtensionContainer {{RecommendedENBItem-ExtIEs}} of TS 36.413: a list of RecommendedENBItemExtIEsExtField values.
type RecommendedENBItemExtIEsExtContainer []RecommendedENBItemExtIEsExtField

// RATRestrictionsItemExtIEsExtContainer is ProtocolExtensionContainer {{RAT-RestrictionsItem-ExtIEs}} of TS 36.413: a list of RATRestrictionsItemExtIEsExtField values.
type RATRestrictionsItemExtIEsExtContainer []RATRestrictionsItemExtIEsExtField

// RequestTypeExtIEsExtContainer is ProtocolExtensionContainer {{RequestType-ExtIEs}} of TS 36.413: a list of RequestTypeExtIEsExtField values.
type RequestTypeExtIEsExtContainer []RequestTypeExtIEsExtField

// RIMTransferExtIEsExtContainer is ProtocolExtensionContainer {{RIMTransfer-ExtIEs}} of TS 36.413: a list of RIMTransferExtIEsExtField values.
type RIMTransferExtIEsExtContainer []RIMTransferExtIEsExtField

// RLFReportInformationExtIEsExtContainer is ProtocolExtensionContainer {{RLFReportInformation-ExtIEs}} of TS 36.413: a list of RLFReportInformationExtIEsExtField values.
type RLFReportInformationExtIEsExtContainer []RLFReportInformationExtIEsExtField

// NGENBExtIEsExtContainer is ProtocolExtensionContainer {{NG-eNB-ExtIEs}} of TS 36.413: a list of NGENBExtIEsExtField values.
type NGENBExtIEsExtContainer []NGENBExtIEsExtField

// MutingPatternInformationExtIEsExtField is ProtocolExtensionField {{MutingPatternInformation-ExtIEs}} of TS 36.413: an extension field.
type MutingPatternInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.MutingPatternInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingPatternInformationExtIEsExtField) WithoutReplay() MutingPatternInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MutingPatternInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MutingPatternInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeMutingPatternInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeMutingPatternInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *MutingPatternInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MutingPatternInformationExtIEsExtField{}
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
	var zero s06.MutingPatternInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeMutingPatternInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeMutingPatternInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeMutingPatternInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NBIoTPagingEDRXInformationExtIEsExtField is ProtocolExtensionField {{NB-IoT-Paging-eDRXInformation-ExtIEs}} of TS 36.413: an extension field.
type NBIoTPagingEDRXInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NBIoTPagingEDRXInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXInformationExtIEsExtField) WithoutReplay() NBIoTPagingEDRXInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NBIoTPagingEDRXInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NBIoTPagingEDRXInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NBIoTPagingEDRXInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NBIoTPagingEDRXInformationExtIEsExtField{}
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
	var zero s06.NBIoTPagingEDRXInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRCGIExtIEsExtField is ProtocolExtensionField {{NR-CGI-ExtIEs}} of TS 36.413: an extension field.
type NRCGIExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NRCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCGIExtIEsExtField) WithoutReplay() NRCGIExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRCGIExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
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
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRCGIExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRCGIExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsExtField{}
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
	var zero s06.NRCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRUESecurityCapabilitiesExtIEsExtField is ProtocolExtensionField {{NRUESecurityCapabilities-ExtIEs}} of TS 36.413: an extension field.
type NRUESecurityCapabilitiesExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NRUESecurityCapabilitiesExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESecurityCapabilitiesExtIEsExtField) WithoutReplay() NRUESecurityCapabilitiesExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRUESecurityCapabilitiesExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRUESecurityCapabilitiesExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRUESecurityCapabilitiesExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESecurityCapabilitiesExtIEsExtField{}
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
	var zero s06.NRUESecurityCapabilitiesExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRV2XServicesAuthorizedExtIEsExtField is ProtocolExtensionField {{NRV2XServicesAuthorized-ExtIEs}} of TS 36.413: an extension field.
type NRV2XServicesAuthorizedExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NRV2XServicesAuthorizedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRV2XServicesAuthorizedExtIEsExtField) WithoutReplay() NRV2XServicesAuthorizedExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRV2XServicesAuthorizedExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRV2XServicesAuthorizedExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRV2XServicesAuthorizedExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRV2XServicesAuthorizedExtIEsExtField{}
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
	var zero s06.NRV2XServicesAuthorizedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRUESidelinkAggregateMaximumBitrateExtIEsExtField is ProtocolExtensionField {{NRUESidelinkAggregateMaximumBitrate-ExtIEs}} of TS 36.413: an extension field.
type NRUESidelinkAggregateMaximumBitrateExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsExtField) WithoutReplay() NRUESidelinkAggregateMaximumBitrateExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESidelinkAggregateMaximumBitrateExtIEsExtField{}
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
	var zero s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PagingAttemptInformationExtIEsExtField is ProtocolExtensionField {{PagingAttemptInformation-ExtIEs}} of TS 36.413: an extension field.
type PagingAttemptInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PagingAttemptInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptInformationExtIEsExtField) WithoutReplay() PagingAttemptInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingAttemptInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingAttemptInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePagingAttemptInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePagingAttemptInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PagingAttemptInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingAttemptInformationExtIEsExtField{}
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
	var zero s06.PagingAttemptInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePagingAttemptInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePagingAttemptInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePagingAttemptInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PagingEDRXInformationExtIEsExtField is ProtocolExtensionField {{Paging-eDRXInformation-ExtIEs}} of TS 36.413: an extension field.
type PagingEDRXInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PagingEDRXInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXInformationExtIEsExtField) WithoutReplay() PagingEDRXInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingEDRXInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingEDRXInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePagingEDRXInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePagingEDRXInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PagingEDRXInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingEDRXInformationExtIEsExtField{}
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
	var zero s06.PagingEDRXInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePagingEDRXInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePagingEDRXInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePagingEDRXInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5QoSParametersExtIEsExtField is ProtocolExtensionField {{PC5QoSParameters-ExtIEs}} of TS 36.413: an extension field.
type PC5QoSParametersExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PC5QoSParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersExtIEsExtField) WithoutReplay() PC5QoSParametersExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5QoSParametersExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5QoSParametersExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5QoSParametersExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5QoSParametersExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5QoSParametersExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSParametersExtIEsExtField{}
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
	var zero s06.PC5QoSParametersExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5QoSParametersExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5QoSParametersExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePC5QoSParametersExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5QoSFlowItemExtIEsExtField is ProtocolExtensionField {{PC5QoSFlowItem-ExtIEs}} of TS 36.413: an extension field.
type PC5QoSFlowItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PC5QoSFlowItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowItemExtIEsExtField) WithoutReplay() PC5QoSFlowItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5QoSFlowItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5QoSFlowItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5QoSFlowItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5QoSFlowItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5QoSFlowItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSFlowItemExtIEsExtField{}
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
	var zero s06.PC5QoSFlowItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5QoSFlowItemExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5QoSFlowItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePC5QoSFlowItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5FlowBitRatesExtIEsExtField is ProtocolExtensionField {{PC5FlowBitRates-ExtIEs}} of TS 36.413: an extension field.
type PC5FlowBitRatesExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PC5FlowBitRatesExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5FlowBitRatesExtIEsExtField) WithoutReplay() PC5FlowBitRatesExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5FlowBitRatesExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5FlowBitRatesExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5FlowBitRatesExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5FlowBitRatesExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5FlowBitRatesExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5FlowBitRatesExtIEsExtField{}
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
	var zero s06.PC5FlowBitRatesExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5FlowBitRatesExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5FlowBitRatesExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePC5FlowBitRatesExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PLMNAreaBasedQMCExtIEsExtField is ProtocolExtensionField {{PLMNAreaBasedQMC-ExtIEs}} of TS 36.413: an extension field.
type PLMNAreaBasedQMCExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PLMNAreaBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNAreaBasedQMCExtIEsExtField) WithoutReplay() PLMNAreaBasedQMCExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PLMNAreaBasedQMCExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PLMNAreaBasedQMCExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePLMNAreaBasedQMCExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePLMNAreaBasedQMCExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PLMNAreaBasedQMCExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PLMNAreaBasedQMCExtIEsExtField{}
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
	var zero s06.PLMNAreaBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePLMNAreaBasedQMCExtIEsValueMethodReason(zero, v.Id), s06.BridgePLMNAreaBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePLMNAreaBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ProSeAuthorizedExtIEsExtField is ProtocolExtensionField {{ProSeAuthorized-ExtIEs}} of TS 36.413: an extension field.
type ProSeAuthorizedExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.ProSeAuthorizedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeAuthorizedExtIEsExtField) WithoutReplay() ProSeAuthorizedExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ProSeAuthorizedExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ProSeAuthorizedExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeProSeAuthorizedExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeProSeAuthorizedExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ProSeAuthorizedExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProSeAuthorizedExtIEsExtField{}
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
	var zero s06.ProSeAuthorizedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeProSeAuthorizedExtIEsValueMethodReason(zero, v.Id), s06.BridgeProSeAuthorizedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeProSeAuthorizedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PSCellInformationExtIEsExtField is ProtocolExtensionField {{PSCellInformation-ExtIEs}} of TS 36.413: an extension field.
type PSCellInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.PSCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSCellInformationExtIEsExtField) WithoutReplay() PSCellInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PSCellInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PSCellInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePSCellInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePSCellInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PSCellInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PSCellInformationExtIEsExtField{}
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
	var zero s06.PSCellInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePSCellInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePSCellInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgePSCellInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedCellsForPagingExtIEsExtField is ProtocolExtensionField {{RecommendedCellsForPaging-ExtIEs}} of TS 36.413: an extension field.
type RecommendedCellsForPagingExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RecommendedCellsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingExtIEsExtField) WithoutReplay() RecommendedCellsForPagingExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedCellsForPagingExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedCellsForPagingExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedCellsForPagingExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedCellsForPagingExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedCellsForPagingExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPagingExtIEsExtField{}
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
	var zero s06.RecommendedCellsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedCellsForPagingExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedCellsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRecommendedCellsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedCellsForPagingItemExtIEsExtField is ProtocolExtensionField {{RecommendedCellsForPagingItem-ExtIEs}} of TS 36.413: an extension field.
type RecommendedCellsForPagingItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RecommendedCellsForPagingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingItemExtIEsExtField) WithoutReplay() RecommendedCellsForPagingItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedCellsForPagingItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedCellsForPagingItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedCellsForPagingItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPagingItemExtIEsExtField{}
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
	var zero s06.RecommendedCellsForPagingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedENBsForPagingExtIEsExtField is ProtocolExtensionField {{RecommendedENBsForPaging-ExtIEs}} of TS 36.413: an extension field.
type RecommendedENBsForPagingExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RecommendedENBsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBsForPagingExtIEsExtField) WithoutReplay() RecommendedENBsForPagingExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedENBsForPagingExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedENBsForPagingExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedENBsForPagingExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedENBsForPagingExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedENBsForPagingExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBsForPagingExtIEsExtField{}
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
	var zero s06.RecommendedENBsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedENBsForPagingExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedENBsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRecommendedENBsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedENBItemExtIEsExtField is ProtocolExtensionField {{RecommendedENBItem-ExtIEs}} of TS 36.413: an extension field.
type RecommendedENBItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RecommendedENBItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBItemExtIEsExtField) WithoutReplay() RecommendedENBItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedENBItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedENBItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedENBItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedENBItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedENBItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBItemExtIEsExtField{}
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
	var zero s06.RecommendedENBItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedENBItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedENBItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRecommendedENBItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RATRestrictionsItemExtIEsExtField is ProtocolExtensionField {{RAT-RestrictionsItem-ExtIEs}} of TS 36.413: an extension field.
type RATRestrictionsItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RATRestrictionsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsItemExtIEsExtField) WithoutReplay() RATRestrictionsItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RATRestrictionsItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RATRestrictionsItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRATRestrictionsItemExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRATRestrictionsItemExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RATRestrictionsItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RATRestrictionsItemExtIEsExtField{}
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
	var zero s06.RATRestrictionsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRATRestrictionsItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRATRestrictionsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRATRestrictionsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RequestTypeExtIEsExtField is ProtocolExtensionField {{RequestType-ExtIEs}} of TS 36.413: an extension field.
type RequestTypeExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s08.RequestTypeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeExtIEsExtField) WithoutReplay() RequestTypeExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RequestTypeExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RequestTypeExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s08.BridgeRequestTypeExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s08.BridgeRequestTypeExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RequestTypeExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestTypeExtIEsExtField{}
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
	var zero s08.RequestTypeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s08.BridgeRequestTypeExtIEsValueMethodReason(zero, v.Id), s08.BridgeRequestTypeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s08.BridgeRequestTypeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RIMTransferExtIEsExtField is ProtocolExtensionField {{RIMTransfer-ExtIEs}} of TS 36.413: an extension field.
type RIMTransferExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RIMTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMTransferExtIEsExtField) WithoutReplay() RIMTransferExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RIMTransferExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RIMTransferExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRIMTransferExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRIMTransferExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RIMTransferExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RIMTransferExtIEsExtField{}
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
	var zero s06.RIMTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRIMTransferExtIEsValueMethodReason(zero, v.Id), s06.BridgeRIMTransferExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRIMTransferExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RLFReportInformationExtIEsExtField is ProtocolExtensionField {{RLFReportInformation-ExtIEs}} of TS 36.413: an extension field.
type RLFReportInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.RLFReportInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RLFReportInformationExtIEsExtField) WithoutReplay() RLFReportInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RLFReportInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RLFReportInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRLFReportInformationExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRLFReportInformationExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RLFReportInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RLFReportInformationExtIEsExtField{}
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
	var zero s06.RLFReportInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRLFReportInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeRLFReportInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeRLFReportInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NGENBExtIEsExtField is ProtocolExtensionField {{NG-eNB-ExtIEs}} of TS 36.413: an extension field.
type NGENBExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue s06.NGENBExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NGENBExtIEsExtField) WithoutReplay() NGENBExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NGENBExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NGENBExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNGENBExtIEsValueMethodMatchesID(v.ExtensionValue, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNGENBExtIEsValueMethodEncodeFresh(v.ExtensionValue, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NGENBExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NGENBExtIEsExtField{}
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
	var zero s06.NGENBExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNGENBExtIEsValueMethodReason(zero, v.Id), s06.BridgeNGENBExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := s06.BridgeNGENBExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MeasurementThresholdL1LoggedMDTExtIEField is ProtocolIE-Field {{MeasurementThresholdL1LoggedMDT-ExtIEs}} of TS 36.413: an information element field.
type MeasurementThresholdL1LoggedMDTExtIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.MeasurementThresholdL1LoggedMDTExtIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEField) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MeasurementThresholdL1LoggedMDTExtIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MeasurementThresholdL1LoggedMDTExtIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *MeasurementThresholdL1LoggedMDTExtIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementThresholdL1LoggedMDTExtIEField{}
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
	var zero s06.MeasurementThresholdL1LoggedMDTExtIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodReason(zero, v.Id), s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding binds ProSeUEtoNetworkRelaying to the ProSeAuthorized-ExtIEs object set of TS 36.413.
type ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.ProSeUEtoNetworkRelayingValueCodec
	inject func(s00.ProSeUEtoNetworkRelaying,

	) s06.ProSeAuthorizedExtIEsValue

	get func(*s06.ProSeAuthorizedExtIEsValue,

	) (*s00.ProSeUEtoNetworkRelaying,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding) Codec() s01.ProSeUEtoNetworkRelayingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding) New(value s00.ProSeUEtoNetworkRelaying,

) (ProSeAuthorizedExtIEsExtField, error) {
	if b.inject == nil {
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ProSeAuthorizedExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding) Get(field *ProSeAuthorizedExtIEsExtField) (*s00.ProSeUEtoNetworkRelaying,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding binds NBIoTRLFReportContainer to the RLFReportInformation-ExtIEs object set of TS 36.413.
type RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.NBIoTRLFReportContainerValueCodec
	inject func(s00.NBIoTRLFReportContainer,

	) s06.RLFReportInformationExtIEsValue

	get func(*s06.RLFReportInformationExtIEsValue,

	) (*s00.NBIoTRLFReportContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding) Codec() s01.NBIoTRLFReportContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding) New(value s00.NBIoTRLFReportContainer,

) (RLFReportInformationExtIEsExtField, error) {
	if b.inject == nil {
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTRLFReportContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return RLFReportInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding) Get(field *RLFReportInformationExtIEsExtField) (*s00.NBIoTRLFReportContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding binds RequestTypeAdditionalInfo to the RequestType-ExtIEs object set of TS 36.413.
type RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.RequestTypeAdditionalInfoValueCodec
	inject func(s00.RequestTypeAdditionalInfo,

	) s08.RequestTypeExtIEsValue

	get func(*s08.RequestTypeExtIEsValue,

	) (*s00.RequestTypeAdditionalInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding) Codec() s02.RequestTypeAdditionalInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding) New(value s00.RequestTypeAdditionalInfo,

) (RequestTypeExtIEsExtField, error) {
	if b.inject == nil {
		return RequestTypeExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestTypeExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RequestTypeExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RequestTypeExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return RequestTypeExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding) Get(field *RequestTypeExtIEsExtField) (*s00.RequestTypeAdditionalInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// MMECPRelocationIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the MMECPRelocationIndicationIEs object set of TS 36.413.
type MMECPRelocationIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) s11.MMECPRelocationIndicationIEValue

	get func(*s11.MMECPRelocationIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMECPRelocationIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMECPRelocationIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMECPRelocationIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (s11.MMECPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s11.MMECPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMECPRelocationIndicationMMEUES1APIDIEBinding) Get(field *s11.MMECPRelocationIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASDeliveryIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the NASDeliveryIndicationIEs object set of TS 36.413.
type NASDeliveryIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) NASDeliveryIndicationIEValue

	get func(*NASDeliveryIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASDeliveryIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASDeliveryIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b NASDeliveryIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (NASDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASDeliveryIndicationMMEUES1APIDIEBinding) Get(field *NASDeliveryIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASDeliveryIndicationENBUES1APIDIEBinding binds ENBUES1APID to the NASDeliveryIndicationIEs object set of TS 36.413.
type NASDeliveryIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) NASDeliveryIndicationIEValue

	get func(*NASDeliveryIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASDeliveryIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASDeliveryIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b NASDeliveryIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (NASDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASDeliveryIndicationENBUES1APIDIEBinding) Get(field *NASDeliveryIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MutingPatternInformationExtIEsIEField uses the ProtocolIE-Field shape for object set MutingPatternInformation-ExtIEs of TS 36.413.
type MutingPatternInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.MutingPatternInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingPatternInformationExtIEsIEField) WithoutReplay() MutingPatternInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MutingPatternInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MutingPatternInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeMutingPatternInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeMutingPatternInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *MutingPatternInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MutingPatternInformationExtIEsIEField{}
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
	var zero s06.MutingPatternInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeMutingPatternInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeMutingPatternInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeMutingPatternInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MutingPatternInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set MutingPatternInformation-ExtIEs of TS 36.413: a list of MutingPatternInformationExtIEsIEField values.
type MutingPatternInformationExtIEsIEContainer []MutingPatternInformationExtIEsIEField

// NBIoTPagingEDRXInformationExtIEsIEField uses the ProtocolIE-Field shape for object set NB-IoT-Paging-eDRXInformation-ExtIEs of TS 36.413.
type NBIoTPagingEDRXInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NBIoTPagingEDRXInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXInformationExtIEsIEField) WithoutReplay() NBIoTPagingEDRXInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NBIoTPagingEDRXInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NBIoTPagingEDRXInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NBIoTPagingEDRXInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NBIoTPagingEDRXInformationExtIEsIEField{}
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
	var zero s06.NBIoTPagingEDRXInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NBIoTPagingEDRXInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set NB-IoT-Paging-eDRXInformation-ExtIEs of TS 36.413: a list of NBIoTPagingEDRXInformationExtIEsIEField values.
type NBIoTPagingEDRXInformationExtIEsIEContainer []NBIoTPagingEDRXInformationExtIEsIEField

// NGENBExtIEsIEField uses the ProtocolIE-Field shape for object set NG-eNB-ExtIEs of TS 36.413.
type NGENBExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NGENBExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NGENBExtIEsIEField) WithoutReplay() NGENBExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NGENBExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NGENBExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNGENBExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNGENBExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NGENBExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NGENBExtIEsIEField{}
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
	var zero s06.NGENBExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNGENBExtIEsValueMethodReason(zero, v.Id), s06.BridgeNGENBExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNGENBExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NGENBExtIEsIEContainer uses the ProtocolIE-Container shape for object set NG-eNB-ExtIEs of TS 36.413: a list of NGENBExtIEsIEField values.
type NGENBExtIEsIEContainer []NGENBExtIEsIEField

// NRCGIExtIEsIEField uses the ProtocolIE-Field shape for object set NR-CGI-ExtIEs of TS 36.413.
type NRCGIExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NRCGIExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCGIExtIEsIEField) WithoutReplay() NRCGIExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRCGIExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
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
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRCGIExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRCGIExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRCGIExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGIExtIEsIEField{}
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
	var zero s06.NRCGIExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRCGIExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRCGIExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNRCGIExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRCGIExtIEsIEContainer uses the ProtocolIE-Container shape for object set NR-CGI-ExtIEs of TS 36.413: a list of NRCGIExtIEsIEField values.
type NRCGIExtIEsIEContainer []NRCGIExtIEsIEField

// NRUESecurityCapabilitiesExtIEsIEField uses the ProtocolIE-Field shape for object set NRUESecurityCapabilities-ExtIEs of TS 36.413.
type NRUESecurityCapabilitiesExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NRUESecurityCapabilitiesExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESecurityCapabilitiesExtIEsIEField) WithoutReplay() NRUESecurityCapabilitiesExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRUESecurityCapabilitiesExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRUESecurityCapabilitiesExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRUESecurityCapabilitiesExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESecurityCapabilitiesExtIEsIEField{}
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
	var zero s06.NRUESecurityCapabilitiesExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRUESecurityCapabilitiesExtIEsIEContainer uses the ProtocolIE-Container shape for object set NRUESecurityCapabilities-ExtIEs of TS 36.413: a list of NRUESecurityCapabilitiesExtIEsIEField values.
type NRUESecurityCapabilitiesExtIEsIEContainer []NRUESecurityCapabilitiesExtIEsIEField

// NRUESidelinkAggregateMaximumBitrateExtIEsIEField uses the ProtocolIE-Field shape for object set NRUESidelinkAggregateMaximumBitrate-ExtIEs of TS 36.413.
type NRUESidelinkAggregateMaximumBitrateExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsIEField) WithoutReplay() NRUESidelinkAggregateMaximumBitrateExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRUESidelinkAggregateMaximumBitrateExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESidelinkAggregateMaximumBitrateExtIEsIEField{}
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
	var zero s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRUESidelinkAggregateMaximumBitrateExtIEsIEContainer uses the ProtocolIE-Container shape for object set NRUESidelinkAggregateMaximumBitrate-ExtIEs of TS 36.413: a list of NRUESidelinkAggregateMaximumBitrateExtIEsIEField values.
type NRUESidelinkAggregateMaximumBitrateExtIEsIEContainer []NRUESidelinkAggregateMaximumBitrateExtIEsIEField

// NRV2XServicesAuthorizedExtIEsIEField uses the ProtocolIE-Field shape for object set NRV2XServicesAuthorized-ExtIEs of TS 36.413.
type NRV2XServicesAuthorizedExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.NRV2XServicesAuthorizedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRV2XServicesAuthorizedExtIEsIEField) WithoutReplay() NRV2XServicesAuthorizedExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NRV2XServicesAuthorizedExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NRV2XServicesAuthorizedExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *NRV2XServicesAuthorizedExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRV2XServicesAuthorizedExtIEsIEField{}
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
	var zero s06.NRV2XServicesAuthorizedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodReason(zero, v.Id), s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// NRV2XServicesAuthorizedExtIEsIEContainer uses the ProtocolIE-Container shape for object set NRV2XServicesAuthorized-ExtIEs of TS 36.413: a list of NRV2XServicesAuthorizedExtIEsIEField values.
type NRV2XServicesAuthorizedExtIEsIEContainer []NRV2XServicesAuthorizedExtIEsIEField

// PC5FlowBitRatesExtIEsIEField uses the ProtocolIE-Field shape for object set PC5FlowBitRates-ExtIEs of TS 36.413.
type PC5FlowBitRatesExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PC5FlowBitRatesExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5FlowBitRatesExtIEsIEField) WithoutReplay() PC5FlowBitRatesExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5FlowBitRatesExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5FlowBitRatesExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5FlowBitRatesExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5FlowBitRatesExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5FlowBitRatesExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5FlowBitRatesExtIEsIEField{}
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
	var zero s06.PC5FlowBitRatesExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5FlowBitRatesExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5FlowBitRatesExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePC5FlowBitRatesExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5FlowBitRatesExtIEsIEContainer uses the ProtocolIE-Container shape for object set PC5FlowBitRates-ExtIEs of TS 36.413: a list of PC5FlowBitRatesExtIEsIEField values.
type PC5FlowBitRatesExtIEsIEContainer []PC5FlowBitRatesExtIEsIEField

// PC5QoSFlowItemExtIEsIEField uses the ProtocolIE-Field shape for object set PC5QoSFlowItem-ExtIEs of TS 36.413.
type PC5QoSFlowItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PC5QoSFlowItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowItemExtIEsIEField) WithoutReplay() PC5QoSFlowItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5QoSFlowItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5QoSFlowItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5QoSFlowItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5QoSFlowItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5QoSFlowItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSFlowItemExtIEsIEField{}
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
	var zero s06.PC5QoSFlowItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5QoSFlowItemExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5QoSFlowItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePC5QoSFlowItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5QoSFlowItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set PC5QoSFlowItem-ExtIEs of TS 36.413: a list of PC5QoSFlowItemExtIEsIEField values.
type PC5QoSFlowItemExtIEsIEContainer []PC5QoSFlowItemExtIEsIEField

// PC5QoSParametersExtIEsIEField uses the ProtocolIE-Field shape for object set PC5QoSParameters-ExtIEs of TS 36.413.
type PC5QoSParametersExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PC5QoSParametersExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersExtIEsIEField) WithoutReplay() PC5QoSParametersExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PC5QoSParametersExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PC5QoSParametersExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePC5QoSParametersExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePC5QoSParametersExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PC5QoSParametersExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSParametersExtIEsIEField{}
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
	var zero s06.PC5QoSParametersExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePC5QoSParametersExtIEsValueMethodReason(zero, v.Id), s06.BridgePC5QoSParametersExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePC5QoSParametersExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PC5QoSParametersExtIEsIEContainer uses the ProtocolIE-Container shape for object set PC5QoSParameters-ExtIEs of TS 36.413: a list of PC5QoSParametersExtIEsIEField values.
type PC5QoSParametersExtIEsIEContainer []PC5QoSParametersExtIEsIEField

// PLMNAreaBasedQMCExtIEsIEField uses the ProtocolIE-Field shape for object set PLMNAreaBasedQMC-ExtIEs of TS 36.413.
type PLMNAreaBasedQMCExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PLMNAreaBasedQMCExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNAreaBasedQMCExtIEsIEField) WithoutReplay() PLMNAreaBasedQMCExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PLMNAreaBasedQMCExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PLMNAreaBasedQMCExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePLMNAreaBasedQMCExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePLMNAreaBasedQMCExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PLMNAreaBasedQMCExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PLMNAreaBasedQMCExtIEsIEField{}
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
	var zero s06.PLMNAreaBasedQMCExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePLMNAreaBasedQMCExtIEsValueMethodReason(zero, v.Id), s06.BridgePLMNAreaBasedQMCExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePLMNAreaBasedQMCExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PLMNAreaBasedQMCExtIEsIEContainer uses the ProtocolIE-Container shape for object set PLMNAreaBasedQMC-ExtIEs of TS 36.413: a list of PLMNAreaBasedQMCExtIEsIEField values.
type PLMNAreaBasedQMCExtIEsIEContainer []PLMNAreaBasedQMCExtIEsIEField

// PSCellInformationExtIEsIEField uses the ProtocolIE-Field shape for object set PSCellInformation-ExtIEs of TS 36.413.
type PSCellInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PSCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSCellInformationExtIEsIEField) WithoutReplay() PSCellInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PSCellInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PSCellInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePSCellInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePSCellInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PSCellInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PSCellInformationExtIEsIEField{}
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
	var zero s06.PSCellInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePSCellInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePSCellInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePSCellInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PSCellInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set PSCellInformation-ExtIEs of TS 36.413: a list of PSCellInformationExtIEsIEField values.
type PSCellInformationExtIEsIEContainer []PSCellInformationExtIEsIEField

// PagingAttemptInformationExtIEsIEField uses the ProtocolIE-Field shape for object set PagingAttemptInformation-ExtIEs of TS 36.413.
type PagingAttemptInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PagingAttemptInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptInformationExtIEsIEField) WithoutReplay() PagingAttemptInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingAttemptInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingAttemptInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePagingAttemptInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePagingAttemptInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PagingAttemptInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingAttemptInformationExtIEsIEField{}
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
	var zero s06.PagingAttemptInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePagingAttemptInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePagingAttemptInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePagingAttemptInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PagingAttemptInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set PagingAttemptInformation-ExtIEs of TS 36.413: a list of PagingAttemptInformationExtIEsIEField values.
type PagingAttemptInformationExtIEsIEContainer []PagingAttemptInformationExtIEsIEField

// PagingEDRXInformationExtIEsIEField uses the ProtocolIE-Field shape for object set Paging-eDRXInformation-ExtIEs of TS 36.413.
type PagingEDRXInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.PagingEDRXInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXInformationExtIEsIEField) WithoutReplay() PagingEDRXInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingEDRXInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingEDRXInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgePagingEDRXInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgePagingEDRXInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PagingEDRXInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingEDRXInformationExtIEsIEField{}
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
	var zero s06.PagingEDRXInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgePagingEDRXInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgePagingEDRXInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgePagingEDRXInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// PagingEDRXInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set Paging-eDRXInformation-ExtIEs of TS 36.413: a list of PagingEDRXInformationExtIEsIEField values.
type PagingEDRXInformationExtIEsIEContainer []PagingEDRXInformationExtIEsIEField

// ProSeAuthorizedExtIEsIEField uses the ProtocolIE-Field shape for object set ProSeAuthorized-ExtIEs of TS 36.413.
type ProSeAuthorizedExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.ProSeAuthorizedExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeAuthorizedExtIEsIEField) WithoutReplay() ProSeAuthorizedExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ProSeAuthorizedExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ProSeAuthorizedExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeProSeAuthorizedExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeProSeAuthorizedExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ProSeAuthorizedExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProSeAuthorizedExtIEsIEField{}
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
	var zero s06.ProSeAuthorizedExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeProSeAuthorizedExtIEsValueMethodReason(zero, v.Id), s06.BridgeProSeAuthorizedExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeProSeAuthorizedExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ProSeAuthorizedExtIEsIEContainer uses the ProtocolIE-Container shape for object set ProSeAuthorized-ExtIEs of TS 36.413: a list of ProSeAuthorizedExtIEsIEField values.
type ProSeAuthorizedExtIEsIEContainer []ProSeAuthorizedExtIEsIEField

// RATRestrictionsItemExtIEsIEField uses the ProtocolIE-Field shape for object set RAT-RestrictionsItem-ExtIEs of TS 36.413.
type RATRestrictionsItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RATRestrictionsItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsItemExtIEsIEField) WithoutReplay() RATRestrictionsItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RATRestrictionsItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RATRestrictionsItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRATRestrictionsItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRATRestrictionsItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RATRestrictionsItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RATRestrictionsItemExtIEsIEField{}
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
	var zero s06.RATRestrictionsItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRATRestrictionsItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRATRestrictionsItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRATRestrictionsItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RATRestrictionsItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set RAT-RestrictionsItem-ExtIEs of TS 36.413: a list of RATRestrictionsItemExtIEsIEField values.
type RATRestrictionsItemExtIEsIEContainer []RATRestrictionsItemExtIEsIEField

// RIMTransferExtIEsIEField uses the ProtocolIE-Field shape for object set RIMTransfer-ExtIEs of TS 36.413.
type RIMTransferExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RIMTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMTransferExtIEsIEField) WithoutReplay() RIMTransferExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RIMTransferExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RIMTransferExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRIMTransferExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRIMTransferExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RIMTransferExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RIMTransferExtIEsIEField{}
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
	var zero s06.RIMTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRIMTransferExtIEsValueMethodReason(zero, v.Id), s06.BridgeRIMTransferExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRIMTransferExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RIMTransferExtIEsIEContainer uses the ProtocolIE-Container shape for object set RIMTransfer-ExtIEs of TS 36.413: a list of RIMTransferExtIEsIEField values.
type RIMTransferExtIEsIEContainer []RIMTransferExtIEsIEField

// RLFReportInformationExtIEsIEField uses the ProtocolIE-Field shape for object set RLFReportInformation-ExtIEs of TS 36.413.
type RLFReportInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RLFReportInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RLFReportInformationExtIEsIEField) WithoutReplay() RLFReportInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RLFReportInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RLFReportInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRLFReportInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRLFReportInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RLFReportInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RLFReportInformationExtIEsIEField{}
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
	var zero s06.RLFReportInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRLFReportInformationExtIEsValueMethodReason(zero, v.Id), s06.BridgeRLFReportInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRLFReportInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RLFReportInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set RLFReportInformation-ExtIEs of TS 36.413: a list of RLFReportInformationExtIEsIEField values.
type RLFReportInformationExtIEsIEContainer []RLFReportInformationExtIEsIEField

// RecommendedCellsForPagingItemExtIEsIEField uses the ProtocolIE-Field shape for object set RecommendedCellsForPagingItem-ExtIEs of TS 36.413.
type RecommendedCellsForPagingItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RecommendedCellsForPagingItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingItemExtIEsIEField) WithoutReplay() RecommendedCellsForPagingItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedCellsForPagingItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedCellsForPagingItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedCellsForPagingItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPagingItemExtIEsIEField{}
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
	var zero s06.RecommendedCellsForPagingItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRecommendedCellsForPagingItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedCellsForPagingItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set RecommendedCellsForPagingItem-ExtIEs of TS 36.413: a list of RecommendedCellsForPagingItemExtIEsIEField values.
type RecommendedCellsForPagingItemExtIEsIEContainer []RecommendedCellsForPagingItemExtIEsIEField

// RecommendedCellsForPagingExtIEsIEField uses the ProtocolIE-Field shape for object set RecommendedCellsForPaging-ExtIEs of TS 36.413.
type RecommendedCellsForPagingExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RecommendedCellsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingExtIEsIEField) WithoutReplay() RecommendedCellsForPagingExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedCellsForPagingExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedCellsForPagingExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedCellsForPagingExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedCellsForPagingExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedCellsForPagingExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedCellsForPagingExtIEsIEField{}
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
	var zero s06.RecommendedCellsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedCellsForPagingExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedCellsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRecommendedCellsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedCellsForPagingExtIEsIEContainer uses the ProtocolIE-Container shape for object set RecommendedCellsForPaging-ExtIEs of TS 36.413: a list of RecommendedCellsForPagingExtIEsIEField values.
type RecommendedCellsForPagingExtIEsIEContainer []RecommendedCellsForPagingExtIEsIEField

// RecommendedENBItemExtIEsIEField uses the ProtocolIE-Field shape for object set RecommendedENBItem-ExtIEs of TS 36.413.
type RecommendedENBItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RecommendedENBItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBItemExtIEsIEField) WithoutReplay() RecommendedENBItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedENBItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedENBItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedENBItemExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedENBItemExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedENBItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBItemExtIEsIEField{}
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
	var zero s06.RecommendedENBItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedENBItemExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedENBItemExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRecommendedENBItemExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedENBItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set RecommendedENBItem-ExtIEs of TS 36.413: a list of RecommendedENBItemExtIEsIEField values.
type RecommendedENBItemExtIEsIEContainer []RecommendedENBItemExtIEsIEField

// RecommendedENBsForPagingExtIEsIEField uses the ProtocolIE-Field shape for object set RecommendedENBsForPaging-ExtIEs of TS 36.413.
type RecommendedENBsForPagingExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s06.RecommendedENBsForPagingExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBsForPagingExtIEsIEField) WithoutReplay() RecommendedENBsForPagingExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RecommendedENBsForPagingExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RecommendedENBsForPagingExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s06.BridgeRecommendedENBsForPagingExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s06.BridgeRecommendedENBsForPagingExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RecommendedENBsForPagingExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBsForPagingExtIEsIEField{}
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
	var zero s06.RecommendedENBsForPagingExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s06.BridgeRecommendedENBsForPagingExtIEsValueMethodReason(zero, v.Id), s06.BridgeRecommendedENBsForPagingExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s06.BridgeRecommendedENBsForPagingExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RecommendedENBsForPagingExtIEsIEContainer uses the ProtocolIE-Container shape for object set RecommendedENBsForPaging-ExtIEs of TS 36.413: a list of RecommendedENBsForPagingExtIEsIEField values.
type RecommendedENBsForPagingExtIEsIEContainer []RecommendedENBsForPagingExtIEsIEField

// RequestTypeExtIEsIEField uses the ProtocolIE-Field shape for object set RequestType-ExtIEs of TS 36.413.
type RequestTypeExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s08.RequestTypeExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeExtIEsIEField) WithoutReplay() RequestTypeExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RequestTypeExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RequestTypeExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	if !s08.BridgeRequestTypeExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s08.BridgeRequestTypeExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *RequestTypeExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestTypeExtIEsIEField{}
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
	var zero s08.RequestTypeExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s08.BridgeRequestTypeExtIEsValueMethodReason(zero, v.Id), s08.BridgeRequestTypeExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s08.BridgeRequestTypeExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// RequestTypeExtIEsIEContainer uses the ProtocolIE-Container shape for object set RequestType-ExtIEs of TS 36.413: a list of RequestTypeExtIEsIEField values.
type RequestTypeExtIEsIEContainer []RequestTypeExtIEsIEField

// MMECPRelocationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMECPRelocationIndicationIEValueERABIEContainerList].
type MMECPRelocationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueERABIEContainerList, error)
	encode  func(MMECPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMECPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) New(value MMECPRelocationIndicationIEValueERABIEContainerList) (MMECPRelocationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value MMECPRelocationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMECPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value MMECPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMECPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type MMECPRelocationIndicationIEValueERABIEContainerList []MMECPRelocationIndicationIEValueProtocolIESingleContainer

// MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, error)
	encode  func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot)
	compare func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) New(value MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MeasurementThresholdL1LoggedMDT-ExtIEs}} of TS 36.413: a list of information element fields.
type MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList []MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer

// MeasurementThresholdL1LoggedMDTExtIEContainer is ProtocolIE-Container {{MeasurementThresholdL1LoggedMDT-ExtIEs}} of TS 36.413: a list of MeasurementThresholdL1LoggedMDTExtIEField values.
type MeasurementThresholdL1LoggedMDTExtIEContainer []MeasurementThresholdL1LoggedMDTExtIEField

// NASDeliveryIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[NASDeliveryIndicationIEValueERABIEContainerList].
type NASDeliveryIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueERABIEContainerList, error)
	encode  func(NASDeliveryIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndicationIEValueERABIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationIEValueERABIEContainerListValueCodec) New(value NASDeliveryIndicationIEValueERABIEContainerList) (NASDeliveryIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value NASDeliveryIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value NASDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value NASDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{NASDeliveryIndicationIEs}} of TS 36.413: a list of information element fields.
type NASDeliveryIndicationIEValueERABIEContainerList []NASDeliveryIndicationIEValueProtocolIESingleContainer

// MutingPatternInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[MutingPatternInformationExtIEsExtField].
type MutingPatternInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MutingPatternInformationExtIEsExtField, error)
	encode  func(MutingPatternInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MutingPatternInformationExtIEsExtField, aper.DecodeState) (MutingPatternInformationExtIEsExtField, aper.Snapshot)
	compare func(MutingPatternInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MutingPatternInformationExtIEsExtFieldValueCodec) New(value MutingPatternInformationExtIEsExtField) (MutingPatternInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return MutingPatternInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MutingPatternInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MutingPatternInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MutingPatternInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MutingPatternInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MutingPatternInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MutingPatternInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MutingPatternInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MutingPatternInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MutingPatternInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MutingPatternInformationExtIEsExtFieldValueCodec) EncodeAPER(value MutingPatternInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MutingPatternInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value MutingPatternInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MutingPatternInformationExtIEsExtFieldValueCodec) encodeChanged(value MutingPatternInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[NBIoTPagingEDRXInformationExtIEsExtField].
type NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtField, error)
	encode  func(NBIoTPagingEDRXInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NBIoTPagingEDRXInformationExtIEsExtField, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot)
	compare func(NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) New(value NBIoTPagingEDRXInformationExtIEsExtField) (NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) EncodeAPER(value NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value NBIoTPagingEDRXInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) encodeChanged(value NBIoTPagingEDRXInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NGENBExtIEsExtFieldValueCodec is the concrete ValueCodec[NGENBExtIEsExtField].
type NGENBExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NGENBExtIEsExtField, error)
	encode  func(NGENBExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NGENBExtIEsExtField, aper.DecodeState) (NGENBExtIEsExtField, aper.Snapshot)
	compare func(NGENBExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NGENBExtIEsExtFieldValueCodec) New(value NGENBExtIEsExtField) (NGENBExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NGENBExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NGENBExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NGENBExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NGENBExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NGENBExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NGENBExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NGENBExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NGENBExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NGENBExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NGENBExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NGENBExtIEsExtFieldValueCodec) EncodeAPER(value NGENBExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NGENBExtIEsExtFieldValueCodec) encodeBudgetValue(value NGENBExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NGENBExtIEsExtFieldValueCodec) encodeChanged(value NGENBExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRCGIExtIEsExtFieldValueCodec is the concrete ValueCodec[NRCGIExtIEsExtField].
type NRCGIExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRCGIExtIEsExtField, error)
	encode  func(NRCGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRCGIExtIEsExtField, aper.DecodeState) (NRCGIExtIEsExtField, aper.Snapshot)
	compare func(NRCGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRCGIExtIEsExtFieldValueCodec) New(value NRCGIExtIEsExtField) (NRCGIExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NRCGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRCGIExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCGIExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRCGIExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRCGIExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRCGIExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRCGIExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRCGIExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRCGIExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRCGIExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRCGIExtIEsExtFieldValueCodec) EncodeAPER(value NRCGIExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRCGIExtIEsExtFieldValueCodec) encodeBudgetValue(value NRCGIExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRCGIExtIEsExtFieldValueCodec) encodeChanged(value NRCGIExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESecurityCapabilitiesExtIEsExtFieldValueCodec is the concrete ValueCodec[NRUESecurityCapabilitiesExtIEsExtField].
type NRUESecurityCapabilitiesExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtField, error)
	encode  func(NRUESecurityCapabilitiesExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESecurityCapabilitiesExtIEsExtField, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot)
	compare func(NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) New(value NRUESecurityCapabilitiesExtIEsExtField) (NRUESecurityCapabilitiesExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESecurityCapabilitiesExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESecurityCapabilitiesExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) EncodeAPER(value NRUESecurityCapabilitiesExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) encodeBudgetValue(value NRUESecurityCapabilitiesExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) encodeChanged(value NRUESecurityCapabilitiesExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec is the concrete ValueCodec[NRUESidelinkAggregateMaximumBitrateExtIEsExtField].
type NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtField, error)
	encode  func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot)
	compare func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) New(value NRUESidelinkAggregateMaximumBitrateExtIEsExtField) (NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) EncodeAPER(value NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) encodeBudgetValue(value NRUESidelinkAggregateMaximumBitrateExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) encodeChanged(value NRUESidelinkAggregateMaximumBitrateExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRV2XServicesAuthorizedExtIEsExtFieldValueCodec is the concrete ValueCodec[NRV2XServicesAuthorizedExtIEsExtField].
type NRV2XServicesAuthorizedExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtField, error)
	encode  func(NRV2XServicesAuthorizedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRV2XServicesAuthorizedExtIEsExtField, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot)
	compare func(NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) New(value NRV2XServicesAuthorizedExtIEsExtField) (NRV2XServicesAuthorizedExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRV2XServicesAuthorizedExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRV2XServicesAuthorizedExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) EncodeAPER(value NRV2XServicesAuthorizedExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) encodeBudgetValue(value NRV2XServicesAuthorizedExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) encodeChanged(value NRV2XServicesAuthorizedExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5FlowBitRatesExtIEsExtFieldValueCodec is the concrete ValueCodec[PC5FlowBitRatesExtIEsExtField].
type PC5FlowBitRatesExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5FlowBitRatesExtIEsExtField, error)
	encode  func(PC5FlowBitRatesExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5FlowBitRatesExtIEsExtField, aper.DecodeState) (PC5FlowBitRatesExtIEsExtField, aper.Snapshot)
	compare func(PC5FlowBitRatesExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5FlowBitRatesExtIEsExtFieldValueCodec) New(value PC5FlowBitRatesExtIEsExtField) (PC5FlowBitRatesExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5FlowBitRatesExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5FlowBitRatesExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5FlowBitRatesExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5FlowBitRatesExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5FlowBitRatesExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5FlowBitRatesExtIEsExtFieldValueCodec) EncodeAPER(value PC5FlowBitRatesExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5FlowBitRatesExtIEsExtFieldValueCodec) encodeBudgetValue(value PC5FlowBitRatesExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5FlowBitRatesExtIEsExtFieldValueCodec) encodeChanged(value PC5FlowBitRatesExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSFlowItemExtIEsExtFieldValueCodec is the concrete ValueCodec[PC5QoSFlowItemExtIEsExtField].
type PC5QoSFlowItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSFlowItemExtIEsExtField, error)
	encode  func(PC5QoSFlowItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSFlowItemExtIEsExtField, aper.DecodeState) (PC5QoSFlowItemExtIEsExtField, aper.Snapshot)
	compare func(PC5QoSFlowItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSFlowItemExtIEsExtFieldValueCodec) New(value PC5QoSFlowItemExtIEsExtField) (PC5QoSFlowItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSFlowItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSFlowItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSFlowItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSFlowItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSFlowItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSFlowItemExtIEsExtFieldValueCodec) EncodeAPER(value PC5QoSFlowItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSFlowItemExtIEsExtFieldValueCodec) encodeBudgetValue(value PC5QoSFlowItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSFlowItemExtIEsExtFieldValueCodec) encodeChanged(value PC5QoSFlowItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSParametersExtIEsExtFieldValueCodec is the concrete ValueCodec[PC5QoSParametersExtIEsExtField].
type PC5QoSParametersExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSParametersExtIEsExtField, error)
	encode  func(PC5QoSParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSParametersExtIEsExtField, aper.DecodeState) (PC5QoSParametersExtIEsExtField, aper.Snapshot)
	compare func(PC5QoSParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSParametersExtIEsExtFieldValueCodec) New(value PC5QoSParametersExtIEsExtField) (PC5QoSParametersExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PC5QoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSParametersExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSParametersExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSParametersExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSParametersExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSParametersExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSParametersExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSParametersExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSParametersExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSParametersExtIEsExtFieldValueCodec) EncodeAPER(value PC5QoSParametersExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSParametersExtIEsExtFieldValueCodec) encodeBudgetValue(value PC5QoSParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSParametersExtIEsExtFieldValueCodec) encodeChanged(value PC5QoSParametersExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PLMNAreaBasedQMCExtIEsExtFieldValueCodec is the concrete ValueCodec[PLMNAreaBasedQMCExtIEsExtField].
type PLMNAreaBasedQMCExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtField, error)
	encode  func(PLMNAreaBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PLMNAreaBasedQMCExtIEsExtField, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot)
	compare func(PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PLMNAreaBasedQMCExtIEsExtFieldValueCodec) New(value PLMNAreaBasedQMCExtIEsExtField) (PLMNAreaBasedQMCExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PLMNAreaBasedQMCExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNAreaBasedQMCExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PLMNAreaBasedQMCExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PLMNAreaBasedQMCExtIEsExtFieldValueCodec) EncodeAPER(value PLMNAreaBasedQMCExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PLMNAreaBasedQMCExtIEsExtFieldValueCodec) encodeBudgetValue(value PLMNAreaBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PLMNAreaBasedQMCExtIEsExtFieldValueCodec) encodeChanged(value PLMNAreaBasedQMCExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PSCellInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[PSCellInformationExtIEsExtField].
type PSCellInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PSCellInformationExtIEsExtField, error)
	encode  func(PSCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PSCellInformationExtIEsExtField, aper.DecodeState) (PSCellInformationExtIEsExtField, aper.Snapshot)
	compare func(PSCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PSCellInformationExtIEsExtFieldValueCodec) New(value PSCellInformationExtIEsExtField) (PSCellInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PSCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PSCellInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PSCellInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PSCellInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PSCellInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PSCellInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PSCellInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PSCellInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PSCellInformationExtIEsExtFieldValueCodec) EncodeAPER(value PSCellInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PSCellInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value PSCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PSCellInformationExtIEsExtFieldValueCodec) encodeChanged(value PSCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingAttemptInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[PagingAttemptInformationExtIEsExtField].
type PagingAttemptInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingAttemptInformationExtIEsExtField, error)
	encode  func(PagingAttemptInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingAttemptInformationExtIEsExtField, aper.DecodeState) (PagingAttemptInformationExtIEsExtField, aper.Snapshot)
	compare func(PagingAttemptInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingAttemptInformationExtIEsExtFieldValueCodec) New(value PagingAttemptInformationExtIEsExtField) (PagingAttemptInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PagingAttemptInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAttemptInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAttemptInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAttemptInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingAttemptInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAttemptInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAttemptInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAttemptInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAttemptInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAttemptInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingAttemptInformationExtIEsExtFieldValueCodec) EncodeAPER(value PagingAttemptInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingAttemptInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value PagingAttemptInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingAttemptInformationExtIEsExtFieldValueCodec) encodeChanged(value PagingAttemptInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingEDRXInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[PagingEDRXInformationExtIEsExtField].
type PagingEDRXInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingEDRXInformationExtIEsExtField, error)
	encode  func(PagingEDRXInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingEDRXInformationExtIEsExtField, aper.DecodeState) (PagingEDRXInformationExtIEsExtField, aper.Snapshot)
	compare func(PagingEDRXInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingEDRXInformationExtIEsExtFieldValueCodec) New(value PagingEDRXInformationExtIEsExtField) (PagingEDRXInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return PagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingEDRXInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingEDRXInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingEDRXInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingEDRXInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingEDRXInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingEDRXInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingEDRXInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingEDRXInformationExtIEsExtFieldValueCodec) EncodeAPER(value PagingEDRXInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingEDRXInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value PagingEDRXInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingEDRXInformationExtIEsExtFieldValueCodec) encodeChanged(value PagingEDRXInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeAuthorizedExtIEsExtFieldValueCodec is the concrete ValueCodec[ProSeAuthorizedExtIEsExtField].
type ProSeAuthorizedExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ProSeAuthorizedExtIEsExtField, error)
	encode  func(ProSeAuthorizedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ProSeAuthorizedExtIEsExtField, aper.DecodeState) (ProSeAuthorizedExtIEsExtField, aper.Snapshot)
	compare func(ProSeAuthorizedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeAuthorizedExtIEsExtFieldValueCodec) New(value ProSeAuthorizedExtIEsExtField) (ProSeAuthorizedExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ProSeAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeAuthorizedExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeAuthorizedExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeAuthorizedExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeAuthorizedExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeAuthorizedExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeAuthorizedExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeAuthorizedExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeAuthorizedExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeAuthorizedExtIEsExtFieldValueCodec) EncodeAPER(value ProSeAuthorizedExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ProSeAuthorizedExtIEsExtFieldValueCodec) encodeBudgetValue(value ProSeAuthorizedExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeAuthorizedExtIEsExtFieldValueCodec) encodeChanged(value ProSeAuthorizedExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RATRestrictionsItemExtIEsExtFieldValueCodec is the concrete ValueCodec[RATRestrictionsItemExtIEsExtField].
type RATRestrictionsItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RATRestrictionsItemExtIEsExtField, error)
	encode  func(RATRestrictionsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RATRestrictionsItemExtIEsExtField, aper.DecodeState) (RATRestrictionsItemExtIEsExtField, aper.Snapshot)
	compare func(RATRestrictionsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RATRestrictionsItemExtIEsExtFieldValueCodec) New(value RATRestrictionsItemExtIEsExtField) (RATRestrictionsItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RATRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RATRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RATRestrictionsItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RATRestrictionsItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RATRestrictionsItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RATRestrictionsItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RATRestrictionsItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RATRestrictionsItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RATRestrictionsItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RATRestrictionsItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RATRestrictionsItemExtIEsExtFieldValueCodec) EncodeAPER(value RATRestrictionsItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RATRestrictionsItemExtIEsExtFieldValueCodec) encodeBudgetValue(value RATRestrictionsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RATRestrictionsItemExtIEsExtFieldValueCodec) encodeChanged(value RATRestrictionsItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RIMTransferExtIEsExtFieldValueCodec is the concrete ValueCodec[RIMTransferExtIEsExtField].
type RIMTransferExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RIMTransferExtIEsExtField, error)
	encode  func(RIMTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RIMTransferExtIEsExtField, aper.DecodeState) (RIMTransferExtIEsExtField, aper.Snapshot)
	compare func(RIMTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMTransferExtIEsExtFieldValueCodec) New(value RIMTransferExtIEsExtField) (RIMTransferExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RIMTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RIMTransferExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RIMTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RIMTransferExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMTransferExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RIMTransferExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RIMTransferExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RIMTransferExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RIMTransferExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RIMTransferExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMTransferExtIEsExtFieldValueCodec) EncodeAPER(value RIMTransferExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RIMTransferExtIEsExtFieldValueCodec) encodeBudgetValue(value RIMTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMTransferExtIEsExtFieldValueCodec) encodeChanged(value RIMTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RLFReportInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[RLFReportInformationExtIEsExtField].
type RLFReportInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RLFReportInformationExtIEsExtField, error)
	encode  func(RLFReportInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RLFReportInformationExtIEsExtField, aper.DecodeState) (RLFReportInformationExtIEsExtField, aper.Snapshot)
	compare func(RLFReportInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RLFReportInformationExtIEsExtFieldValueCodec) New(value RLFReportInformationExtIEsExtField) (RLFReportInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RLFReportInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RLFReportInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RLFReportInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RLFReportInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RLFReportInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RLFReportInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RLFReportInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RLFReportInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RLFReportInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RLFReportInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RLFReportInformationExtIEsExtFieldValueCodec) EncodeAPER(value RLFReportInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RLFReportInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value RLFReportInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RLFReportInformationExtIEsExtFieldValueCodec) encodeChanged(value RLFReportInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellsForPagingExtIEsExtFieldValueCodec is the concrete ValueCodec[RecommendedCellsForPagingExtIEsExtField].
type RecommendedCellsForPagingExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtField, error)
	encode  func(RecommendedCellsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellsForPagingExtIEsExtField, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtField, aper.Snapshot)
	compare func(RecommendedCellsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellsForPagingExtIEsExtFieldValueCodec) New(value RecommendedCellsForPagingExtIEsExtField) (RecommendedCellsForPagingExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellsForPagingExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellsForPagingExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellsForPagingExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellsForPagingExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellsForPagingExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellsForPagingExtIEsExtFieldValueCodec) EncodeAPER(value RecommendedCellsForPagingExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedCellsForPagingExtIEsExtFieldValueCodec) encodeBudgetValue(value RecommendedCellsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellsForPagingExtIEsExtFieldValueCodec) encodeChanged(value RecommendedCellsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellsForPagingItemExtIEsExtFieldValueCodec is the concrete ValueCodec[RecommendedCellsForPagingItemExtIEsExtField].
type RecommendedCellsForPagingItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtField, error)
	encode  func(RecommendedCellsForPagingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellsForPagingItemExtIEsExtField, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot)
	compare func(RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) New(value RecommendedCellsForPagingItemExtIEsExtField) (RecommendedCellsForPagingItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellsForPagingItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellsForPagingItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) EncodeAPER(value RecommendedCellsForPagingItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) encodeBudgetValue(value RecommendedCellsForPagingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) encodeChanged(value RecommendedCellsForPagingItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBItemExtIEsExtFieldValueCodec is the concrete ValueCodec[RecommendedENBItemExtIEsExtField].
type RecommendedENBItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedENBItemExtIEsExtField, error)
	encode  func(RecommendedENBItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedENBItemExtIEsExtField, aper.DecodeState) (RecommendedENBItemExtIEsExtField, aper.Snapshot)
	compare func(RecommendedENBItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBItemExtIEsExtFieldValueCodec) New(value RecommendedENBItemExtIEsExtField) (RecommendedENBItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RecommendedENBItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedENBItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedENBItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedENBItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedENBItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedENBItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedENBItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedENBItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedENBItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBItemExtIEsExtFieldValueCodec) EncodeAPER(value RecommendedENBItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedENBItemExtIEsExtFieldValueCodec) encodeBudgetValue(value RecommendedENBItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBItemExtIEsExtFieldValueCodec) encodeChanged(value RecommendedENBItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBsForPagingExtIEsExtFieldValueCodec is the concrete ValueCodec[RecommendedENBsForPagingExtIEsExtField].
type RecommendedENBsForPagingExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtField, error)
	encode  func(RecommendedENBsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedENBsForPagingExtIEsExtField, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtField, aper.Snapshot)
	compare func(RecommendedENBsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBsForPagingExtIEsExtFieldValueCodec) New(value RecommendedENBsForPagingExtIEsExtField) (RecommendedENBsForPagingExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedENBsForPagingExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBsForPagingExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedENBsForPagingExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedENBsForPagingExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedENBsForPagingExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBsForPagingExtIEsExtFieldValueCodec) EncodeAPER(value RecommendedENBsForPagingExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedENBsForPagingExtIEsExtFieldValueCodec) encodeBudgetValue(value RecommendedENBsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBsForPagingExtIEsExtFieldValueCodec) encodeChanged(value RecommendedENBsForPagingExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RequestTypeExtIEsExtFieldValueCodec is the concrete ValueCodec[RequestTypeExtIEsExtField].
type RequestTypeExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestTypeExtIEsExtField, error)
	encode  func(RequestTypeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestTypeExtIEsExtField, aper.DecodeState) (RequestTypeExtIEsExtField, aper.Snapshot)
	compare func(RequestTypeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestTypeExtIEsExtFieldValueCodec) New(value RequestTypeExtIEsExtField) (RequestTypeExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return RequestTypeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestTypeExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestTypeExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestTypeExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestTypeExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestTypeExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestTypeExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestTypeExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestTypeExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestTypeExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestTypeExtIEsExtFieldValueCodec) EncodeAPER(value RequestTypeExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RequestTypeExtIEsExtFieldValueCodec) encodeBudgetValue(value RequestTypeExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestTypeExtIEsExtFieldValueCodec) encodeChanged(value RequestTypeExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MutingPatternInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[MutingPatternInformationExtIEsExtContainer].
type MutingPatternInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MutingPatternInformationExtIEsExtContainer, error)
	encode  func(MutingPatternInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MutingPatternInformationExtIEsExtContainer, aper.DecodeState) (MutingPatternInformationExtIEsExtContainer, aper.Snapshot)
	compare func(MutingPatternInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MutingPatternInformationExtIEsExtContainerValueCodec) New(value MutingPatternInformationExtIEsExtContainer) (MutingPatternInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return MutingPatternInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MutingPatternInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MutingPatternInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MutingPatternInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MutingPatternInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MutingPatternInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MutingPatternInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MutingPatternInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MutingPatternInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MutingPatternInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MutingPatternInformationExtIEsExtContainerValueCodec) EncodeAPER(value MutingPatternInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MutingPatternInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value MutingPatternInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MutingPatternInformationExtIEsExtContainerValueCodec) encodeChanged(value MutingPatternInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[NBIoTPagingEDRXInformationExtIEsExtContainer].
type NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtContainer, error)
	encode  func(NBIoTPagingEDRXInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NBIoTPagingEDRXInformationExtIEsExtContainer, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot)
	compare func(NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) New(value NBIoTPagingEDRXInformationExtIEsExtContainer) (NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) EncodeAPER(value NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value NBIoTPagingEDRXInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) encodeChanged(value NBIoTPagingEDRXInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NGENBExtIEsExtContainerValueCodec is the concrete ValueCodec[NGENBExtIEsExtContainer].
type NGENBExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NGENBExtIEsExtContainer, error)
	encode  func(NGENBExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NGENBExtIEsExtContainer, aper.DecodeState) (NGENBExtIEsExtContainer, aper.Snapshot)
	compare func(NGENBExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NGENBExtIEsExtContainerValueCodec) New(value NGENBExtIEsExtContainer) (NGENBExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NGENBExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NGENBExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NGENBExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NGENBExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NGENBExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NGENBExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NGENBExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NGENBExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NGENBExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NGENBExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NGENBExtIEsExtContainerValueCodec) EncodeAPER(value NGENBExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NGENBExtIEsExtContainerValueCodec) encodeBudgetValue(value NGENBExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NGENBExtIEsExtContainerValueCodec) encodeChanged(value NGENBExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRCGIExtIEsExtContainerValueCodec is the concrete ValueCodec[NRCGIExtIEsExtContainer].
type NRCGIExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRCGIExtIEsExtContainer, error)
	encode  func(NRCGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRCGIExtIEsExtContainer, aper.DecodeState) (NRCGIExtIEsExtContainer, aper.Snapshot)
	compare func(NRCGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRCGIExtIEsExtContainerValueCodec) New(value NRCGIExtIEsExtContainer) (NRCGIExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NRCGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRCGIExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCGIExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRCGIExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRCGIExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRCGIExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRCGIExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRCGIExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRCGIExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRCGIExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRCGIExtIEsExtContainerValueCodec) EncodeAPER(value NRCGIExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRCGIExtIEsExtContainerValueCodec) encodeBudgetValue(value NRCGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRCGIExtIEsExtContainerValueCodec) encodeChanged(value NRCGIExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESecurityCapabilitiesExtIEsExtContainerValueCodec is the concrete ValueCodec[NRUESecurityCapabilitiesExtIEsExtContainer].
type NRUESecurityCapabilitiesExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtContainer, error)
	encode  func(NRUESecurityCapabilitiesExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESecurityCapabilitiesExtIEsExtContainer, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot)
	compare func(NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) New(value NRUESecurityCapabilitiesExtIEsExtContainer) (NRUESecurityCapabilitiesExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESecurityCapabilitiesExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESecurityCapabilitiesExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) EncodeAPER(value NRUESecurityCapabilitiesExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) encodeBudgetValue(value NRUESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) encodeChanged(value NRUESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec is the concrete ValueCodec[NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer].
type NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, error)
	encode  func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot)
	compare func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) New(value NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) EncodeAPER(value NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) encodeBudgetValue(value NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) encodeChanged(value NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRV2XServicesAuthorizedExtIEsExtContainerValueCodec is the concrete ValueCodec[NRV2XServicesAuthorizedExtIEsExtContainer].
type NRV2XServicesAuthorizedExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtContainer, error)
	encode  func(NRV2XServicesAuthorizedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRV2XServicesAuthorizedExtIEsExtContainer, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot)
	compare func(NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) New(value NRV2XServicesAuthorizedExtIEsExtContainer) (NRV2XServicesAuthorizedExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRV2XServicesAuthorizedExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRV2XServicesAuthorizedExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) EncodeAPER(value NRV2XServicesAuthorizedExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) encodeBudgetValue(value NRV2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) encodeChanged(value NRV2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5FlowBitRatesExtIEsExtContainerValueCodec is the concrete ValueCodec[PC5FlowBitRatesExtIEsExtContainer].
type PC5FlowBitRatesExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5FlowBitRatesExtIEsExtContainer, error)
	encode  func(PC5FlowBitRatesExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5FlowBitRatesExtIEsExtContainer, aper.DecodeState) (PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot)
	compare func(PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5FlowBitRatesExtIEsExtContainerValueCodec) New(value PC5FlowBitRatesExtIEsExtContainer) (PC5FlowBitRatesExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5FlowBitRatesExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5FlowBitRatesExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5FlowBitRatesExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5FlowBitRatesExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5FlowBitRatesExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5FlowBitRatesExtIEsExtContainerValueCodec) EncodeAPER(value PC5FlowBitRatesExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5FlowBitRatesExtIEsExtContainerValueCodec) encodeBudgetValue(value PC5FlowBitRatesExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5FlowBitRatesExtIEsExtContainerValueCodec) encodeChanged(value PC5FlowBitRatesExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSFlowItemExtIEsExtContainerValueCodec is the concrete ValueCodec[PC5QoSFlowItemExtIEsExtContainer].
type PC5QoSFlowItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSFlowItemExtIEsExtContainer, error)
	encode  func(PC5QoSFlowItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSFlowItemExtIEsExtContainer, aper.DecodeState) (PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot)
	compare func(PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSFlowItemExtIEsExtContainerValueCodec) New(value PC5QoSFlowItemExtIEsExtContainer) (PC5QoSFlowItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSFlowItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSFlowItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSFlowItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSFlowItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSFlowItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSFlowItemExtIEsExtContainerValueCodec) EncodeAPER(value PC5QoSFlowItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSFlowItemExtIEsExtContainerValueCodec) encodeBudgetValue(value PC5QoSFlowItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSFlowItemExtIEsExtContainerValueCodec) encodeChanged(value PC5QoSFlowItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSParametersExtIEsExtContainerValueCodec is the concrete ValueCodec[PC5QoSParametersExtIEsExtContainer].
type PC5QoSParametersExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSParametersExtIEsExtContainer, error)
	encode  func(PC5QoSParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSParametersExtIEsExtContainer, aper.DecodeState) (PC5QoSParametersExtIEsExtContainer, aper.Snapshot)
	compare func(PC5QoSParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSParametersExtIEsExtContainerValueCodec) New(value PC5QoSParametersExtIEsExtContainer) (PC5QoSParametersExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PC5QoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSParametersExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSParametersExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSParametersExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSParametersExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSParametersExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSParametersExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSParametersExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSParametersExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSParametersExtIEsExtContainerValueCodec) EncodeAPER(value PC5QoSParametersExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSParametersExtIEsExtContainerValueCodec) encodeBudgetValue(value PC5QoSParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSParametersExtIEsExtContainerValueCodec) encodeChanged(value PC5QoSParametersExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PLMNAreaBasedQMCExtIEsExtContainerValueCodec is the concrete ValueCodec[PLMNAreaBasedQMCExtIEsExtContainer].
type PLMNAreaBasedQMCExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtContainer, error)
	encode  func(PLMNAreaBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PLMNAreaBasedQMCExtIEsExtContainer, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot)
	compare func(PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PLMNAreaBasedQMCExtIEsExtContainerValueCodec) New(value PLMNAreaBasedQMCExtIEsExtContainer) (PLMNAreaBasedQMCExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PLMNAreaBasedQMCExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNAreaBasedQMCExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PLMNAreaBasedQMCExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PLMNAreaBasedQMCExtIEsExtContainerValueCodec) EncodeAPER(value PLMNAreaBasedQMCExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PLMNAreaBasedQMCExtIEsExtContainerValueCodec) encodeBudgetValue(value PLMNAreaBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PLMNAreaBasedQMCExtIEsExtContainerValueCodec) encodeChanged(value PLMNAreaBasedQMCExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PSCellInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[PSCellInformationExtIEsExtContainer].
type PSCellInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PSCellInformationExtIEsExtContainer, error)
	encode  func(PSCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PSCellInformationExtIEsExtContainer, aper.DecodeState) (PSCellInformationExtIEsExtContainer, aper.Snapshot)
	compare func(PSCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PSCellInformationExtIEsExtContainerValueCodec) New(value PSCellInformationExtIEsExtContainer) (PSCellInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PSCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PSCellInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PSCellInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PSCellInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PSCellInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PSCellInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PSCellInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PSCellInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PSCellInformationExtIEsExtContainerValueCodec) EncodeAPER(value PSCellInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PSCellInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value PSCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PSCellInformationExtIEsExtContainerValueCodec) encodeChanged(value PSCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingAttemptInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[PagingAttemptInformationExtIEsExtContainer].
type PagingAttemptInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingAttemptInformationExtIEsExtContainer, error)
	encode  func(PagingAttemptInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingAttemptInformationExtIEsExtContainer, aper.DecodeState) (PagingAttemptInformationExtIEsExtContainer, aper.Snapshot)
	compare func(PagingAttemptInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingAttemptInformationExtIEsExtContainerValueCodec) New(value PagingAttemptInformationExtIEsExtContainer) (PagingAttemptInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PagingAttemptInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAttemptInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAttemptInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAttemptInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingAttemptInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAttemptInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAttemptInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAttemptInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAttemptInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAttemptInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingAttemptInformationExtIEsExtContainerValueCodec) EncodeAPER(value PagingAttemptInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingAttemptInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value PagingAttemptInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingAttemptInformationExtIEsExtContainerValueCodec) encodeChanged(value PagingAttemptInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingEDRXInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[PagingEDRXInformationExtIEsExtContainer].
type PagingEDRXInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingEDRXInformationExtIEsExtContainer, error)
	encode  func(PagingEDRXInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingEDRXInformationExtIEsExtContainer, aper.DecodeState) (PagingEDRXInformationExtIEsExtContainer, aper.Snapshot)
	compare func(PagingEDRXInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingEDRXInformationExtIEsExtContainerValueCodec) New(value PagingEDRXInformationExtIEsExtContainer) (PagingEDRXInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return PagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingEDRXInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingEDRXInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingEDRXInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingEDRXInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingEDRXInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingEDRXInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingEDRXInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingEDRXInformationExtIEsExtContainerValueCodec) EncodeAPER(value PagingEDRXInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingEDRXInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value PagingEDRXInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingEDRXInformationExtIEsExtContainerValueCodec) encodeChanged(value PagingEDRXInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeAuthorizedExtIEsExtContainerValueCodec is the concrete ValueCodec[ProSeAuthorizedExtIEsExtContainer].
type ProSeAuthorizedExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ProSeAuthorizedExtIEsExtContainer, error)
	encode  func(ProSeAuthorizedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ProSeAuthorizedExtIEsExtContainer, aper.DecodeState) (ProSeAuthorizedExtIEsExtContainer, aper.Snapshot)
	compare func(ProSeAuthorizedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeAuthorizedExtIEsExtContainerValueCodec) New(value ProSeAuthorizedExtIEsExtContainer) (ProSeAuthorizedExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ProSeAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeAuthorizedExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeAuthorizedExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeAuthorizedExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeAuthorizedExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeAuthorizedExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeAuthorizedExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeAuthorizedExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeAuthorizedExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeAuthorizedExtIEsExtContainerValueCodec) EncodeAPER(value ProSeAuthorizedExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ProSeAuthorizedExtIEsExtContainerValueCodec) encodeBudgetValue(value ProSeAuthorizedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeAuthorizedExtIEsExtContainerValueCodec) encodeChanged(value ProSeAuthorizedExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RATRestrictionsItemExtIEsExtContainerValueCodec is the concrete ValueCodec[RATRestrictionsItemExtIEsExtContainer].
type RATRestrictionsItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RATRestrictionsItemExtIEsExtContainer, error)
	encode  func(RATRestrictionsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RATRestrictionsItemExtIEsExtContainer, aper.DecodeState) (RATRestrictionsItemExtIEsExtContainer, aper.Snapshot)
	compare func(RATRestrictionsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RATRestrictionsItemExtIEsExtContainerValueCodec) New(value RATRestrictionsItemExtIEsExtContainer) (RATRestrictionsItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RATRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RATRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RATRestrictionsItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RATRestrictionsItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RATRestrictionsItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RATRestrictionsItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RATRestrictionsItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RATRestrictionsItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RATRestrictionsItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RATRestrictionsItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RATRestrictionsItemExtIEsExtContainerValueCodec) EncodeAPER(value RATRestrictionsItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RATRestrictionsItemExtIEsExtContainerValueCodec) encodeBudgetValue(value RATRestrictionsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RATRestrictionsItemExtIEsExtContainerValueCodec) encodeChanged(value RATRestrictionsItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RIMTransferExtIEsExtContainerValueCodec is the concrete ValueCodec[RIMTransferExtIEsExtContainer].
type RIMTransferExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RIMTransferExtIEsExtContainer, error)
	encode  func(RIMTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RIMTransferExtIEsExtContainer, aper.DecodeState) (RIMTransferExtIEsExtContainer, aper.Snapshot)
	compare func(RIMTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMTransferExtIEsExtContainerValueCodec) New(value RIMTransferExtIEsExtContainer) (RIMTransferExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RIMTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RIMTransferExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RIMTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RIMTransferExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMTransferExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RIMTransferExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RIMTransferExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RIMTransferExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RIMTransferExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RIMTransferExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMTransferExtIEsExtContainerValueCodec) EncodeAPER(value RIMTransferExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RIMTransferExtIEsExtContainerValueCodec) encodeBudgetValue(value RIMTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMTransferExtIEsExtContainerValueCodec) encodeChanged(value RIMTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RLFReportInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[RLFReportInformationExtIEsExtContainer].
type RLFReportInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RLFReportInformationExtIEsExtContainer, error)
	encode  func(RLFReportInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RLFReportInformationExtIEsExtContainer, aper.DecodeState) (RLFReportInformationExtIEsExtContainer, aper.Snapshot)
	compare func(RLFReportInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RLFReportInformationExtIEsExtContainerValueCodec) New(value RLFReportInformationExtIEsExtContainer) (RLFReportInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RLFReportInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RLFReportInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RLFReportInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RLFReportInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RLFReportInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RLFReportInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RLFReportInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RLFReportInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RLFReportInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RLFReportInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RLFReportInformationExtIEsExtContainerValueCodec) EncodeAPER(value RLFReportInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RLFReportInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value RLFReportInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RLFReportInformationExtIEsExtContainerValueCodec) encodeChanged(value RLFReportInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellsForPagingExtIEsExtContainerValueCodec is the concrete ValueCodec[RecommendedCellsForPagingExtIEsExtContainer].
type RecommendedCellsForPagingExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtContainer, error)
	encode  func(RecommendedCellsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellsForPagingExtIEsExtContainer, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot)
	compare func(RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellsForPagingExtIEsExtContainerValueCodec) New(value RecommendedCellsForPagingExtIEsExtContainer) (RecommendedCellsForPagingExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellsForPagingExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellsForPagingExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellsForPagingExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellsForPagingExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellsForPagingExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellsForPagingExtIEsExtContainerValueCodec) EncodeAPER(value RecommendedCellsForPagingExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedCellsForPagingExtIEsExtContainerValueCodec) encodeBudgetValue(value RecommendedCellsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellsForPagingExtIEsExtContainerValueCodec) encodeChanged(value RecommendedCellsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedCellsForPagingItemExtIEsExtContainerValueCodec is the concrete ValueCodec[RecommendedCellsForPagingItemExtIEsExtContainer].
type RecommendedCellsForPagingItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtContainer, error)
	encode  func(RecommendedCellsForPagingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedCellsForPagingItemExtIEsExtContainer, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot)
	compare func(RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) New(value RecommendedCellsForPagingItemExtIEsExtContainer) (RecommendedCellsForPagingItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedCellsForPagingItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedCellsForPagingItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) EncodeAPER(value RecommendedCellsForPagingItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) encodeBudgetValue(value RecommendedCellsForPagingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) encodeChanged(value RecommendedCellsForPagingItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBItemExtIEsExtContainerValueCodec is the concrete ValueCodec[RecommendedENBItemExtIEsExtContainer].
type RecommendedENBItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedENBItemExtIEsExtContainer, error)
	encode  func(RecommendedENBItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedENBItemExtIEsExtContainer, aper.DecodeState) (RecommendedENBItemExtIEsExtContainer, aper.Snapshot)
	compare func(RecommendedENBItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBItemExtIEsExtContainerValueCodec) New(value RecommendedENBItemExtIEsExtContainer) (RecommendedENBItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RecommendedENBItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedENBItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedENBItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedENBItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedENBItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedENBItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedENBItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedENBItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedENBItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBItemExtIEsExtContainerValueCodec) EncodeAPER(value RecommendedENBItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedENBItemExtIEsExtContainerValueCodec) encodeBudgetValue(value RecommendedENBItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBItemExtIEsExtContainerValueCodec) encodeChanged(value RecommendedENBItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBsForPagingExtIEsExtContainerValueCodec is the concrete ValueCodec[RecommendedENBsForPagingExtIEsExtContainer].
type RecommendedENBsForPagingExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtContainer, error)
	encode  func(RecommendedENBsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedENBsForPagingExtIEsExtContainer, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtContainer, aper.Snapshot)
	compare func(RecommendedENBsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBsForPagingExtIEsExtContainerValueCodec) New(value RecommendedENBsForPagingExtIEsExtContainer) (RecommendedENBsForPagingExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedENBsForPagingExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBsForPagingExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedENBsForPagingExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedENBsForPagingExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedENBsForPagingExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBsForPagingExtIEsExtContainerValueCodec) EncodeAPER(value RecommendedENBsForPagingExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedENBsForPagingExtIEsExtContainerValueCodec) encodeBudgetValue(value RecommendedENBsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBsForPagingExtIEsExtContainerValueCodec) encodeChanged(value RecommendedENBsForPagingExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RequestTypeExtIEsExtContainerValueCodec is the concrete ValueCodec[RequestTypeExtIEsExtContainer].
type RequestTypeExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestTypeExtIEsExtContainer, error)
	encode  func(RequestTypeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestTypeExtIEsExtContainer, aper.DecodeState) (RequestTypeExtIEsExtContainer, aper.Snapshot)
	compare func(RequestTypeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestTypeExtIEsExtContainerValueCodec) New(value RequestTypeExtIEsExtContainer) (RequestTypeExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return RequestTypeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestTypeExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestTypeExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestTypeExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestTypeExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestTypeExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestTypeExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestTypeExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestTypeExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestTypeExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestTypeExtIEsExtContainerValueCodec) EncodeAPER(value RequestTypeExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RequestTypeExtIEsExtContainerValueCodec) encodeBudgetValue(value RequestTypeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestTypeExtIEsExtContainerValueCodec) encodeChanged(value RequestTypeExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEFieldValueCodec is the concrete ValueCodec[MMECPRelocationIndicationIEField].
type MMECPRelocationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s11.MMECPRelocationIndicationIEField, error)
	encode  func(s11.MMECPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s11.MMECPRelocationIndicationIEField, aper.DecodeState) (s11.MMECPRelocationIndicationIEField, aper.Snapshot)
	compare func(s11.MMECPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationIEFieldValueCodec) New(value s11.MMECPRelocationIndicationIEField) (MMECPRelocationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationIEFieldValueCodec) EncodeAPER(value MMECPRelocationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationIEFieldValueCodec) encodeBudgetValue(value s11.MMECPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationIEFieldValueCodec) encodeChanged(value s11.MMECPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDTExtIEField].
type MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEField, error)
	encode  func(MeasurementThresholdL1LoggedMDTExtIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDTExtIEField, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot)
	compare func(MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) New(value MeasurementThresholdL1LoggedMDTExtIEField) (MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDTExtIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDTExtIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationIEFieldValueCodec is the concrete ValueCodec[NASDeliveryIndicationIEField].
type NASDeliveryIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndicationIEField, error)
	encode  func(NASDeliveryIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndicationIEField, aper.DecodeState) (NASDeliveryIndicationIEField, aper.Snapshot)
	compare func(NASDeliveryIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationIEFieldValueCodec) New(value NASDeliveryIndicationIEField) (NASDeliveryIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationIEFieldValueCodec) EncodeAPER(value NASDeliveryIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationIEFieldValueCodec) encodeBudgetValue(value NASDeliveryIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationIEFieldValueCodec) encodeChanged(value NASDeliveryIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEContainerValueCodec is the concrete ValueCodec[MMECPRelocationIndicationIEContainer].
type MMECPRelocationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, error)
	encode  func(s11.MMECPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s11.MMECPRelocationIndicationIEContainer, aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, aper.Snapshot)
	compare func(s11.MMECPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationIEContainerValueCodec) New(value s11.MMECPRelocationIndicationIEContainer) (MMECPRelocationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationIEContainerValueCodec) EncodeAPER(value MMECPRelocationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationIEContainerValueCodec) encodeBudgetValue(value s11.MMECPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationIEContainerValueCodec) encodeChanged(value s11.MMECPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDTExtIEContainer].
type MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEContainer, error)
	encode  func(MeasurementThresholdL1LoggedMDTExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDTExtIEContainer, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot)
	compare func(MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) New(value MeasurementThresholdL1LoggedMDTExtIEContainer) (MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDTExtIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDTExtIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationIEContainerValueCodec is the concrete ValueCodec[NASDeliveryIndicationIEContainer].
type NASDeliveryIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndicationIEContainer, error)
	encode  func(NASDeliveryIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndicationIEContainer, aper.DecodeState) (NASDeliveryIndicationIEContainer, aper.Snapshot)
	compare func(NASDeliveryIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationIEContainerValueCodec) New(value NASDeliveryIndicationIEContainer) (NASDeliveryIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationIEContainerValueCodec) EncodeAPER(value NASDeliveryIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationIEContainerValueCodec) encodeBudgetValue(value NASDeliveryIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationIEContainerValueCodec) encodeChanged(value NASDeliveryIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMECPRelocationIndicationIEValueProtocolErrorIEContainerList].
type MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value MMECPRelocationIndicationIEValueProtocolErrorIEContainerList) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMECPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type MMECPRelocationIndicationIEValueProtocolErrorIEContainerList []MMECPRelocationIndicationIEValueProtocolIESingleContainer

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, error)
	encode  func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) New(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MeasurementThresholdL1LoggedMDT-ExtIEs}} of TS 36.413: a list of information element fields.
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList []MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer

// NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[NASDeliveryIndicationIEValueProtocolErrorIEContainerList].
type NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value NASDeliveryIndicationIEValueProtocolErrorIEContainerList) (NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value NASDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value NASDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{NASDeliveryIndicationIEs}} of TS 36.413: a list of information element fields.
type NASDeliveryIndicationIEValueProtocolErrorIEContainerList []NASDeliveryIndicationIEValueProtocolIESingleContainer

// MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMECPRelocationIndicationIEValueProtocolIEContainerList].
type MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolIEContainerList, error)
	encode  func(MMECPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) New(value MMECPRelocationIndicationIEValueProtocolIEContainerList) (MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMECPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMECPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMECPRelocationIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMECPRelocationIndicationIEValueProtocolIEContainerList []MMECPRelocationIndicationIEValueProtocolIESingleContainer

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, error)
	encode  func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) New(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MeasurementThresholdL1LoggedMDT-ExtIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList []MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer

// NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[NASDeliveryIndicationIEValueProtocolIEContainerList].
type NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolIEContainerList, error)
	encode  func(NASDeliveryIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndicationIEValueProtocolIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) New(value NASDeliveryIndicationIEValueProtocolIEContainerList) (NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value NASDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value NASDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {NASDeliveryIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type NASDeliveryIndicationIEValueProtocolIEContainerList []NASDeliveryIndicationIEValueProtocolIESingleContainer

// MMECPRelocationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[MMECPRelocationIndicationIEValueERABIEContainerList].
type MMECPRelocationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMECPRelocationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() MMECPRelocationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMECPRelocationIndicationIEs}} of TS 36.413: a single information element field.
type MMECPRelocationIndicationIEValueProtocolIESingleContainer = s11.MMECPRelocationIndicationIEField

// MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[NASDeliveryIndicationIEValueERABIEContainerList].
type NASDeliveryIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASDeliveryIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() NASDeliveryIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{NASDeliveryIndicationIEs}} of TS 36.413: a single information element field.
type NASDeliveryIndicationIEValueProtocolIESingleContainer = NASDeliveryIndicationIEField

// MutingPatternInformationExtIEsExtFieldAPERValue is the concrete APERValue[MutingPatternInformationExtIEsExtField].
type MutingPatternInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MutingPatternInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MutingPatternInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingPatternInformationExtIEsExtFieldAPERValue) WithoutReplay() MutingPatternInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue is the concrete APERValue[NBIoTPagingEDRXInformationExtIEsExtField].
type NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NBIoTPagingEDRXInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue) WithoutReplay() NBIoTPagingEDRXInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NGENBExtIEsExtFieldAPERValue is the concrete APERValue[NGENBExtIEsExtField].
type NGENBExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NGENBExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NGENBExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NGENBExtIEsExtFieldAPERValue) WithoutReplay() NGENBExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCGIExtIEsExtFieldAPERValue is the concrete APERValue[NRCGIExtIEsExtField].
type NRCGIExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRCGIExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRCGIExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCGIExtIEsExtFieldAPERValue) WithoutReplay() NRCGIExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESecurityCapabilitiesExtIEsExtFieldAPERValue is the concrete APERValue[NRUESecurityCapabilitiesExtIEsExtField].
type NRUESecurityCapabilitiesExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRUESecurityCapabilitiesExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESecurityCapabilitiesExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESecurityCapabilitiesExtIEsExtFieldAPERValue) WithoutReplay() NRUESecurityCapabilitiesExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue is the concrete APERValue[NRUESidelinkAggregateMaximumBitrateExtIEsExtField].
type NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRUESidelinkAggregateMaximumBitrateExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue) WithoutReplay() NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRV2XServicesAuthorizedExtIEsExtFieldAPERValue is the concrete APERValue[NRV2XServicesAuthorizedExtIEsExtField].
type NRV2XServicesAuthorizedExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRV2XServicesAuthorizedExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRV2XServicesAuthorizedExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRV2XServicesAuthorizedExtIEsExtFieldAPERValue) WithoutReplay() NRV2XServicesAuthorizedExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5FlowBitRatesExtIEsExtFieldAPERValue is the concrete APERValue[PC5FlowBitRatesExtIEsExtField].
type PC5FlowBitRatesExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5FlowBitRatesExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5FlowBitRatesExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5FlowBitRatesExtIEsExtFieldAPERValue) WithoutReplay() PC5FlowBitRatesExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSFlowItemExtIEsExtFieldAPERValue is the concrete APERValue[PC5QoSFlowItemExtIEsExtField].
type PC5QoSFlowItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5QoSFlowItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSFlowItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowItemExtIEsExtFieldAPERValue) WithoutReplay() PC5QoSFlowItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSParametersExtIEsExtFieldAPERValue is the concrete APERValue[PC5QoSParametersExtIEsExtField].
type PC5QoSParametersExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5QoSParametersExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSParametersExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersExtIEsExtFieldAPERValue) WithoutReplay() PC5QoSParametersExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNAreaBasedQMCExtIEsExtFieldAPERValue is the concrete APERValue[PLMNAreaBasedQMCExtIEsExtField].
type PLMNAreaBasedQMCExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PLMNAreaBasedQMCExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PLMNAreaBasedQMCExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNAreaBasedQMCExtIEsExtFieldAPERValue) WithoutReplay() PLMNAreaBasedQMCExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PSCellInformationExtIEsExtFieldAPERValue is the concrete APERValue[PSCellInformationExtIEsExtField].
type PSCellInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PSCellInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PSCellInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSCellInformationExtIEsExtFieldAPERValue) WithoutReplay() PSCellInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAttemptInformationExtIEsExtFieldAPERValue is the concrete APERValue[PagingAttemptInformationExtIEsExtField].
type PagingAttemptInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingAttemptInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAttemptInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptInformationExtIEsExtFieldAPERValue) WithoutReplay() PagingAttemptInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingEDRXInformationExtIEsExtFieldAPERValue is the concrete APERValue[PagingEDRXInformationExtIEsExtField].
type PagingEDRXInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingEDRXInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingEDRXInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXInformationExtIEsExtFieldAPERValue) WithoutReplay() PagingEDRXInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeAuthorizedExtIEsExtFieldAPERValue is the concrete APERValue[ProSeAuthorizedExtIEsExtField].
type ProSeAuthorizedExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ProSeAuthorizedExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeAuthorizedExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeAuthorizedExtIEsExtFieldAPERValue) WithoutReplay() ProSeAuthorizedExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RATRestrictionsItemExtIEsExtFieldAPERValue is the concrete APERValue[RATRestrictionsItemExtIEsExtField].
type RATRestrictionsItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RATRestrictionsItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RATRestrictionsItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsItemExtIEsExtFieldAPERValue) WithoutReplay() RATRestrictionsItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RIMTransferExtIEsExtFieldAPERValue is the concrete APERValue[RIMTransferExtIEsExtField].
type RIMTransferExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RIMTransferExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RIMTransferExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMTransferExtIEsExtFieldAPERValue) WithoutReplay() RIMTransferExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RLFReportInformationExtIEsExtFieldAPERValue is the concrete APERValue[RLFReportInformationExtIEsExtField].
type RLFReportInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RLFReportInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RLFReportInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RLFReportInformationExtIEsExtFieldAPERValue) WithoutReplay() RLFReportInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellsForPagingExtIEsExtFieldAPERValue is the concrete APERValue[RecommendedCellsForPagingExtIEsExtField].
type RecommendedCellsForPagingExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellsForPagingExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellsForPagingExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingExtIEsExtFieldAPERValue) WithoutReplay() RecommendedCellsForPagingExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellsForPagingItemExtIEsExtFieldAPERValue is the concrete APERValue[RecommendedCellsForPagingItemExtIEsExtField].
type RecommendedCellsForPagingItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellsForPagingItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellsForPagingItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingItemExtIEsExtFieldAPERValue) WithoutReplay() RecommendedCellsForPagingItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedENBItemExtIEsExtFieldAPERValue is the concrete APERValue[RecommendedENBItemExtIEsExtField].
type RecommendedENBItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedENBItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBItemExtIEsExtFieldAPERValue) WithoutReplay() RecommendedENBItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedENBsForPagingExtIEsExtFieldAPERValue is the concrete APERValue[RecommendedENBsForPagingExtIEsExtField].
type RecommendedENBsForPagingExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedENBsForPagingExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBsForPagingExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBsForPagingExtIEsExtFieldAPERValue) WithoutReplay() RecommendedENBsForPagingExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestTypeExtIEsExtFieldAPERValue is the concrete APERValue[RequestTypeExtIEsExtField].
type RequestTypeExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RequestTypeExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestTypeExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeExtIEsExtFieldAPERValue) WithoutReplay() RequestTypeExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MutingPatternInformationExtIEsExtContainerAPERValue is the concrete APERValue[MutingPatternInformationExtIEsExtContainer].
type MutingPatternInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MutingPatternInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MutingPatternInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingPatternInformationExtIEsExtContainerAPERValue) WithoutReplay() MutingPatternInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue is the concrete APERValue[NBIoTPagingEDRXInformationExtIEsExtContainer].
type NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NBIoTPagingEDRXInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue) WithoutReplay() NBIoTPagingEDRXInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NGENBExtIEsExtContainerAPERValue is the concrete APERValue[NGENBExtIEsExtContainer].
type NGENBExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NGENBExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NGENBExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NGENBExtIEsExtContainerAPERValue) WithoutReplay() NGENBExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCGIExtIEsExtContainerAPERValue is the concrete APERValue[NRCGIExtIEsExtContainer].
type NRCGIExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRCGIExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRCGIExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCGIExtIEsExtContainerAPERValue) WithoutReplay() NRCGIExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESecurityCapabilitiesExtIEsExtContainerAPERValue is the concrete APERValue[NRUESecurityCapabilitiesExtIEsExtContainer].
type NRUESecurityCapabilitiesExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRUESecurityCapabilitiesExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESecurityCapabilitiesExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESecurityCapabilitiesExtIEsExtContainerAPERValue) WithoutReplay() NRUESecurityCapabilitiesExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue is the concrete APERValue[NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer].
type NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue) WithoutReplay() NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRV2XServicesAuthorizedExtIEsExtContainerAPERValue is the concrete APERValue[NRV2XServicesAuthorizedExtIEsExtContainer].
type NRV2XServicesAuthorizedExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NRV2XServicesAuthorizedExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRV2XServicesAuthorizedExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRV2XServicesAuthorizedExtIEsExtContainerAPERValue) WithoutReplay() NRV2XServicesAuthorizedExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5FlowBitRatesExtIEsExtContainerAPERValue is the concrete APERValue[PC5FlowBitRatesExtIEsExtContainer].
type PC5FlowBitRatesExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5FlowBitRatesExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5FlowBitRatesExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5FlowBitRatesExtIEsExtContainerAPERValue) WithoutReplay() PC5FlowBitRatesExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSFlowItemExtIEsExtContainerAPERValue is the concrete APERValue[PC5QoSFlowItemExtIEsExtContainer].
type PC5QoSFlowItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5QoSFlowItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSFlowItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowItemExtIEsExtContainerAPERValue) WithoutReplay() PC5QoSFlowItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSParametersExtIEsExtContainerAPERValue is the concrete APERValue[PC5QoSParametersExtIEsExtContainer].
type PC5QoSParametersExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PC5QoSParametersExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSParametersExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersExtIEsExtContainerAPERValue) WithoutReplay() PC5QoSParametersExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNAreaBasedQMCExtIEsExtContainerAPERValue is the concrete APERValue[PLMNAreaBasedQMCExtIEsExtContainer].
type PLMNAreaBasedQMCExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PLMNAreaBasedQMCExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PLMNAreaBasedQMCExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNAreaBasedQMCExtIEsExtContainerAPERValue) WithoutReplay() PLMNAreaBasedQMCExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PSCellInformationExtIEsExtContainerAPERValue is the concrete APERValue[PSCellInformationExtIEsExtContainer].
type PSCellInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PSCellInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PSCellInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSCellInformationExtIEsExtContainerAPERValue) WithoutReplay() PSCellInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAttemptInformationExtIEsExtContainerAPERValue is the concrete APERValue[PagingAttemptInformationExtIEsExtContainer].
type PagingAttemptInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingAttemptInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAttemptInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptInformationExtIEsExtContainerAPERValue) WithoutReplay() PagingAttemptInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingEDRXInformationExtIEsExtContainerAPERValue is the concrete APERValue[PagingEDRXInformationExtIEsExtContainer].
type PagingEDRXInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingEDRXInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingEDRXInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXInformationExtIEsExtContainerAPERValue) WithoutReplay() PagingEDRXInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeAuthorizedExtIEsExtContainerAPERValue is the concrete APERValue[ProSeAuthorizedExtIEsExtContainer].
type ProSeAuthorizedExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ProSeAuthorizedExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeAuthorizedExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeAuthorizedExtIEsExtContainerAPERValue) WithoutReplay() ProSeAuthorizedExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RATRestrictionsItemExtIEsExtContainerAPERValue is the concrete APERValue[RATRestrictionsItemExtIEsExtContainer].
type RATRestrictionsItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RATRestrictionsItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RATRestrictionsItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsItemExtIEsExtContainerAPERValue) WithoutReplay() RATRestrictionsItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RIMTransferExtIEsExtContainerAPERValue is the concrete APERValue[RIMTransferExtIEsExtContainer].
type RIMTransferExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RIMTransferExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RIMTransferExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMTransferExtIEsExtContainerAPERValue) WithoutReplay() RIMTransferExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RLFReportInformationExtIEsExtContainerAPERValue is the concrete APERValue[RLFReportInformationExtIEsExtContainer].
type RLFReportInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RLFReportInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RLFReportInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RLFReportInformationExtIEsExtContainerAPERValue) WithoutReplay() RLFReportInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellsForPagingExtIEsExtContainerAPERValue is the concrete APERValue[RecommendedCellsForPagingExtIEsExtContainer].
type RecommendedCellsForPagingExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellsForPagingExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellsForPagingExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingExtIEsExtContainerAPERValue) WithoutReplay() RecommendedCellsForPagingExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedCellsForPagingItemExtIEsExtContainerAPERValue is the concrete APERValue[RecommendedCellsForPagingItemExtIEsExtContainer].
type RecommendedCellsForPagingItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedCellsForPagingItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedCellsForPagingItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedCellsForPagingItemExtIEsExtContainerAPERValue) WithoutReplay() RecommendedCellsForPagingItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedENBItemExtIEsExtContainerAPERValue is the concrete APERValue[RecommendedENBItemExtIEsExtContainer].
type RecommendedENBItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedENBItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBItemExtIEsExtContainerAPERValue) WithoutReplay() RecommendedENBItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedENBsForPagingExtIEsExtContainerAPERValue is the concrete APERValue[RecommendedENBsForPagingExtIEsExtContainer].
type RecommendedENBsForPagingExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RecommendedENBsForPagingExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBsForPagingExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBsForPagingExtIEsExtContainerAPERValue) WithoutReplay() RecommendedENBsForPagingExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestTypeExtIEsExtContainerAPERValue is the concrete APERValue[RequestTypeExtIEsExtContainer].
type RequestTypeExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RequestTypeExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestTypeExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeExtIEsExtContainerAPERValue) WithoutReplay() RequestTypeExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationIEFieldAPERValue is the concrete APERValue[MMECPRelocationIndicationIEField].
type MMECPRelocationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         s11.MMECPRelocationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEFieldAPERValue) WithoutReplay() MMECPRelocationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDTExtIEField].
type MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MeasurementThresholdL1LoggedMDTExtIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEFieldAPERValue is the concrete APERValue[NASDeliveryIndicationIEField].
type NASDeliveryIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASDeliveryIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEFieldAPERValue) WithoutReplay() NASDeliveryIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationIEContainerAPERValue is the concrete APERValue[MMECPRelocationIndicationIEContainer].
type MMECPRelocationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         s11.MMECPRelocationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEContainerAPERValue) WithoutReplay() MMECPRelocationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDTExtIEContainer].
type MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MeasurementThresholdL1LoggedMDTExtIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEContainerAPERValue is the concrete APERValue[NASDeliveryIndicationIEContainer].
type NASDeliveryIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASDeliveryIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEContainerAPERValue) WithoutReplay() NASDeliveryIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMECPRelocationIndicationIEValueProtocolErrorIEContainerList].
type MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMECPRelocationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMECPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[NASDeliveryIndicationIEValueProtocolErrorIEContainerList].
type NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASDeliveryIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() NASDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMECPRelocationIndicationIEValueProtocolIEContainerList].
type MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMECPRelocationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMECPRelocationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[NASDeliveryIndicationIEValueProtocolIEContainerList].
type NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASDeliveryIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() NASDeliveryIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APNASDeliveryIndicationIEValue(v *NASDeliveryIndicationIEValue, s *aper.SemanticCapture) {
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
func (v NASDeliveryIndicationIEValue) captureSemantics(s aper.SemanticCapture) NASDeliveryIndicationIEValue {
	BridgeCaptureS1APNASDeliveryIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APNASDeliveryIndicationIEValue(v *NASDeliveryIndicationIEValue, s *aper.SemanticComparison) {
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
func (v NASDeliveryIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APNASDeliveryIndicationIEValue(&v, &s)
	return s
}

type NASDeliveryIndicationIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
}

func (v NASDeliveryIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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

// Opaque returns the retained opaque open value of NASDeliveryIndicationIEValue and reports whether the opaque alternative is selected.
func (v *NASDeliveryIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (NASDeliveryIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASDeliveryIndicationIEs"}}
}
func (NASDeliveryIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
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

// AsMMEUES1APID returns the selected MMEUES1APID value of NASDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASDeliveryIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of NASDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASDeliveryIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v NASDeliveryIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (NASDeliveryIndicationIEValue, error) {
	out := NASDeliveryIndicationIEValue{id: id}
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
func (v NASDeliveryIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v NASDeliveryIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "NASDeliveryIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "NASDeliveryIndicationIEs.id-eNB-UE-S1AP-ID:")
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
		return nil, fmt.Errorf("%s id %d has no value", "NASDeliveryIndicationIEValue:", v.id)
	}
}

type MeasurementThresholdL1LoggedMDTExtIETable struct{}

func MeasurementThresholdL1LoggedMDTExtIEs() MeasurementThresholdL1LoggedMDTExtIETable {
	return MeasurementThresholdL1LoggedMDTExtIETable{}
}

// ID returns the ASN.1 object-set identity of MeasurementThresholdL1LoggedMDTExtIETable.
func (MeasurementThresholdL1LoggedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MeasurementThresholdL1LoggedMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MeasurementThresholdL1LoggedMDTExtIETable.
func (MeasurementThresholdL1LoggedMDTExtIETable) Table() s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable {
	return func() s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable {
		sealed := s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable{}
		*s00.BridgeMeasurementThresholdL1LoggedMDTExtIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MeasurementThresholdL1LoggedMDTExtIETable.
func (t MeasurementThresholdL1LoggedMDTExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MeasurementThresholdL1LoggedMDTExtIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MeasurementThresholdL1LoggedMDTExtIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTExtIEField{}, aper.OperationError(err, "Opaque")
		}
		return MeasurementThresholdL1LoggedMDTExtIEField{Id: id, Criticality: criticality, Value: func() s06.MeasurementThresholdL1LoggedMDTExtIEValue {
			sealed := s06.MeasurementThresholdL1LoggedMDTExtIEValue{}
			*s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldId(&sealed) = id
			*s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldOpaque(&sealed) = opaque
			*s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type MutingPatternInformationExtIETable struct{}

func MutingPatternInformationExtIEs() MutingPatternInformationExtIETable {
	return MutingPatternInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of MutingPatternInformationExtIETable.
func (MutingPatternInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MutingPatternInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MutingPatternInformationExtIETable.
func (MutingPatternInformationExtIETable) Table() s00.MutingPatternInformationExtIEsValueExtensionTable {
	return func() s00.MutingPatternInformationExtIEsValueExtensionTable {
		sealed := s00.MutingPatternInformationExtIEsValueExtensionTable{}
		*s00.BridgeMutingPatternInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MutingPatternInformationExtIETable.
func (t MutingPatternInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (MutingPatternInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MutingPatternInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MutingPatternInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MutingPatternInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return MutingPatternInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.MutingPatternInformationExtIEsValue {
			sealed := s06.MutingPatternInformationExtIEsValue{}
			*s06.BridgeMutingPatternInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgeMutingPatternInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeMutingPatternInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NBIoTPagingEDRXInformationExtIETable struct{}

func NBIoTPagingEDRXInformationExtIEs() NBIoTPagingEDRXInformationExtIETable {
	return NBIoTPagingEDRXInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of NBIoTPagingEDRXInformationExtIETable.
func (NBIoTPagingEDRXInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-Paging-eDRXInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NBIoTPagingEDRXInformationExtIETable.
func (NBIoTPagingEDRXInformationExtIETable) Table() s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable {
	return func() s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable {
		sealed := s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable{}
		*s00.BridgeNBIoTPagingEDRXInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NBIoTPagingEDRXInformationExtIETable.
func (t NBIoTPagingEDRXInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NBIoTPagingEDRXInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NBIoTPagingEDRXInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NBIoTPagingEDRXInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NBIoTPagingEDRXInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NBIoTPagingEDRXInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NBIoTPagingEDRXInformationExtIEsValue {
			sealed := s06.NBIoTPagingEDRXInformationExtIEsValue{}
			*s06.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NGENBExtIETable struct{}

func NGENBExtIEs() NGENBExtIETable { return NGENBExtIETable{} }

// ID returns the ASN.1 object-set identity of NGENBExtIETable.
func (NGENBExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NG-eNB-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NGENBExtIETable.
func (NGENBExtIETable) Table() s00.NGENBExtIEsValueExtensionTable {
	return func() s00.NGENBExtIEsValueExtensionTable {
		sealed := s00.NGENBExtIEsValueExtensionTable{}
		*s00.BridgeNGENBExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NGENBExtIETable.
func (t NGENBExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NGENBExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NGENBExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NGENBExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NGENBExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NGENBExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NGENBExtIEsValue {
			sealed := s06.NGENBExtIEsValue{}
			*s06.BridgeNGENBExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNGENBExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNGENBExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NRCGIExtIETable struct{}

func NRCGIExtIEs() NRCGIExtIETable { return NRCGIExtIETable{} }

// ID returns the ASN.1 object-set identity of NRCGIExtIETable.
func (NRCGIExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NR-CGI-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NRCGIExtIETable.
func (NRCGIExtIETable) Table() s00.NRCGIExtIEsValueExtensionTable {
	return func() s00.NRCGIExtIEsValueExtensionTable {
		sealed := s00.NRCGIExtIEsValueExtensionTable{}
		*s00.BridgeNRCGIExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NRCGIExtIETable.
func (t NRCGIExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NRCGIExtIEsExtField, error) {
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
		return NRCGIExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NRCGIExtIEsValue {
			sealed := s06.NRCGIExtIEsValue{}
			*s06.BridgeNRCGIExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNRCGIExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNRCGIExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NRUESecurityCapabilitiesExtIETable struct{}

func NRUESecurityCapabilitiesExtIEs() NRUESecurityCapabilitiesExtIETable {
	return NRUESecurityCapabilitiesExtIETable{}
}

// ID returns the ASN.1 object-set identity of NRUESecurityCapabilitiesExtIETable.
func (NRUESecurityCapabilitiesExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NRUESecurityCapabilitiesExtIETable.
func (NRUESecurityCapabilitiesExtIETable) Table() s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable {
	return func() s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable {
		sealed := s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable{}
		*s00.BridgeNRUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NRUESecurityCapabilitiesExtIETable.
func (t NRUESecurityCapabilitiesExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NRUESecurityCapabilitiesExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NRUESecurityCapabilitiesExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NRUESecurityCapabilitiesExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NRUESecurityCapabilitiesExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NRUESecurityCapabilitiesExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NRUESecurityCapabilitiesExtIEsValue {
			sealed := s06.NRUESecurityCapabilitiesExtIEsValue{}
			*s06.BridgeNRUESecurityCapabilitiesExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNRUESecurityCapabilitiesExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNRUESecurityCapabilitiesExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NRUESidelinkAggregateMaximumBitrateExtIETable struct{}

func NRUESidelinkAggregateMaximumBitrateExtIEs() NRUESidelinkAggregateMaximumBitrateExtIETable {
	return NRUESidelinkAggregateMaximumBitrateExtIETable{}
}

// ID returns the ASN.1 object-set identity of NRUESidelinkAggregateMaximumBitrateExtIETable.
func (NRUESidelinkAggregateMaximumBitrateExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NRUESidelinkAggregateMaximumBitrateExtIETable.
func (NRUESidelinkAggregateMaximumBitrateExtIETable) Table() s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable {
	return func() s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable {
		sealed := s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable{}
		*s00.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NRUESidelinkAggregateMaximumBitrateExtIETable.
func (t NRUESidelinkAggregateMaximumBitrateExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NRUESidelinkAggregateMaximumBitrateExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NRUESidelinkAggregateMaximumBitrateExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NRUESidelinkAggregateMaximumBitrateExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NRUESidelinkAggregateMaximumBitrateExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue {
			sealed := s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue{}
			*s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NRV2XServicesAuthorizedExtIETable struct{}

func NRV2XServicesAuthorizedExtIEs() NRV2XServicesAuthorizedExtIETable {
	return NRV2XServicesAuthorizedExtIETable{}
}

// ID returns the ASN.1 object-set identity of NRV2XServicesAuthorizedExtIETable.
func (NRV2XServicesAuthorizedExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NRV2XServicesAuthorizedExtIETable.
func (NRV2XServicesAuthorizedExtIETable) Table() s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable {
	return func() s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable {
		sealed := s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable{}
		*s00.BridgeNRV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NRV2XServicesAuthorizedExtIETable.
func (t NRV2XServicesAuthorizedExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (NRV2XServicesAuthorizedExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NRV2XServicesAuthorizedExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NRV2XServicesAuthorizedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NRV2XServicesAuthorizedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return NRV2XServicesAuthorizedExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.NRV2XServicesAuthorizedExtIEsValue {
			sealed := s06.NRV2XServicesAuthorizedExtIEsValue{}
			*s06.BridgeNRV2XServicesAuthorizedExtIEsValueFieldId(&sealed) = id
			*s06.BridgeNRV2XServicesAuthorizedExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeNRV2XServicesAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PC5FlowBitRatesExtIETable struct{}

func PC5FlowBitRatesExtIEs() PC5FlowBitRatesExtIETable { return PC5FlowBitRatesExtIETable{} }

// ID returns the ASN.1 object-set identity of PC5FlowBitRatesExtIETable.
func (PC5FlowBitRatesExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5FlowBitRates-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PC5FlowBitRatesExtIETable.
func (PC5FlowBitRatesExtIETable) Table() s00.PC5FlowBitRatesExtIEsValueExtensionTable {
	return func() s00.PC5FlowBitRatesExtIEsValueExtensionTable {
		sealed := s00.PC5FlowBitRatesExtIEsValueExtensionTable{}
		*s00.BridgePC5FlowBitRatesExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PC5FlowBitRatesExtIETable.
func (t PC5FlowBitRatesExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PC5FlowBitRatesExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PC5FlowBitRatesExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PC5FlowBitRatesExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PC5FlowBitRatesExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PC5FlowBitRatesExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PC5FlowBitRatesExtIEsValue {
			sealed := s06.PC5FlowBitRatesExtIEsValue{}
			*s06.BridgePC5FlowBitRatesExtIEsValueFieldId(&sealed) = id
			*s06.BridgePC5FlowBitRatesExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePC5FlowBitRatesExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PC5QoSFlowItemExtIETable struct{}

func PC5QoSFlowItemExtIEs() PC5QoSFlowItemExtIETable { return PC5QoSFlowItemExtIETable{} }

// ID returns the ASN.1 object-set identity of PC5QoSFlowItemExtIETable.
func (PC5QoSFlowItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSFlowItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PC5QoSFlowItemExtIETable.
func (PC5QoSFlowItemExtIETable) Table() s00.PC5QoSFlowItemExtIEsValueExtensionTable {
	return func() s00.PC5QoSFlowItemExtIEsValueExtensionTable {
		sealed := s00.PC5QoSFlowItemExtIEsValueExtensionTable{}
		*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PC5QoSFlowItemExtIETable.
func (t PC5QoSFlowItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PC5QoSFlowItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PC5QoSFlowItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PC5QoSFlowItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PC5QoSFlowItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PC5QoSFlowItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PC5QoSFlowItemExtIEsValue {
			sealed := s06.PC5QoSFlowItemExtIEsValue{}
			*s06.BridgePC5QoSFlowItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgePC5QoSFlowItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePC5QoSFlowItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PC5QoSParametersExtIETable struct{}

func PC5QoSParametersExtIEs() PC5QoSParametersExtIETable { return PC5QoSParametersExtIETable{} }

// ID returns the ASN.1 object-set identity of PC5QoSParametersExtIETable.
func (PC5QoSParametersExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PC5QoSParametersExtIETable.
func (PC5QoSParametersExtIETable) Table() s00.PC5QoSParametersExtIEsValueExtensionTable {
	return func() s00.PC5QoSParametersExtIEsValueExtensionTable {
		sealed := s00.PC5QoSParametersExtIEsValueExtensionTable{}
		*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PC5QoSParametersExtIETable.
func (t PC5QoSParametersExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PC5QoSParametersExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PC5QoSParametersExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PC5QoSParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PC5QoSParametersExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PC5QoSParametersExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PC5QoSParametersExtIEsValue {
			sealed := s06.PC5QoSParametersExtIEsValue{}
			*s06.BridgePC5QoSParametersExtIEsValueFieldId(&sealed) = id
			*s06.BridgePC5QoSParametersExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePC5QoSParametersExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PLMNAreaBasedQMCExtIETable struct{}

func PLMNAreaBasedQMCExtIEs() PLMNAreaBasedQMCExtIETable { return PLMNAreaBasedQMCExtIETable{} }

// ID returns the ASN.1 object-set identity of PLMNAreaBasedQMCExtIETable.
func (PLMNAreaBasedQMCExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PLMNAreaBasedQMC-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PLMNAreaBasedQMCExtIETable.
func (PLMNAreaBasedQMCExtIETable) Table() s00.PLMNAreaBasedQMCExtIEsValueExtensionTable {
	return func() s00.PLMNAreaBasedQMCExtIEsValueExtensionTable {
		sealed := s00.PLMNAreaBasedQMCExtIEsValueExtensionTable{}
		*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PLMNAreaBasedQMCExtIETable.
func (t PLMNAreaBasedQMCExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PLMNAreaBasedQMCExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PLMNAreaBasedQMCExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PLMNAreaBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PLMNAreaBasedQMCExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PLMNAreaBasedQMCExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PLMNAreaBasedQMCExtIEsValue {
			sealed := s06.PLMNAreaBasedQMCExtIEsValue{}
			*s06.BridgePLMNAreaBasedQMCExtIEsValueFieldId(&sealed) = id
			*s06.BridgePLMNAreaBasedQMCExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePLMNAreaBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PSCellInformationExtIETable struct{}

func PSCellInformationExtIEs() PSCellInformationExtIETable { return PSCellInformationExtIETable{} }

// ID returns the ASN.1 object-set identity of PSCellInformationExtIETable.
func (PSCellInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PSCellInformationExtIETable.
func (PSCellInformationExtIETable) Table() s00.PSCellInformationExtIEsValueExtensionTable {
	return func() s00.PSCellInformationExtIEsValueExtensionTable {
		sealed := s00.PSCellInformationExtIEsValueExtensionTable{}
		*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PSCellInformationExtIETable.
func (t PSCellInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PSCellInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PSCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PSCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PSCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PSCellInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PSCellInformationExtIEsValue {
			sealed := s06.PSCellInformationExtIEsValue{}
			*s06.BridgePSCellInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgePSCellInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PagingEDRXInformationExtIETable struct{}

func PagingEDRXInformationExtIEs() PagingEDRXInformationExtIETable {
	return PagingEDRXInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of PagingEDRXInformationExtIETable.
func (PagingEDRXInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Paging-eDRXInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PagingEDRXInformationExtIETable.
func (PagingEDRXInformationExtIETable) Table() s00.PagingEDRXInformationExtIEsValueExtensionTable {
	return func() s00.PagingEDRXInformationExtIEsValueExtensionTable {
		sealed := s00.PagingEDRXInformationExtIEsValueExtensionTable{}
		*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PagingEDRXInformationExtIETable.
func (t PagingEDRXInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PagingEDRXInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PagingEDRXInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PagingEDRXInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PagingEDRXInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PagingEDRXInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PagingEDRXInformationExtIEsValue {
			sealed := s06.PagingEDRXInformationExtIEsValue{}
			*s06.BridgePagingEDRXInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgePagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type PagingAttemptInformationExtIETable struct{}

func PagingAttemptInformationExtIEs() PagingAttemptInformationExtIETable {
	return PagingAttemptInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of PagingAttemptInformationExtIETable.
func (PagingAttemptInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingAttemptInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PagingAttemptInformationExtIETable.
func (PagingAttemptInformationExtIETable) Table() s00.PagingAttemptInformationExtIEsValueExtensionTable {
	return func() s00.PagingAttemptInformationExtIEsValueExtensionTable {
		sealed := s00.PagingAttemptInformationExtIEsValueExtensionTable{}
		*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PagingAttemptInformationExtIETable.
func (t PagingAttemptInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (PagingAttemptInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PagingAttemptInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PagingAttemptInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PagingAttemptInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return PagingAttemptInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.PagingAttemptInformationExtIEsValue {
			sealed := s06.PagingAttemptInformationExtIEsValue{}
			*s06.BridgePagingAttemptInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgePagingAttemptInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgePagingAttemptInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ProSeAuthorizedExtIETable struct{}

func ProSeAuthorizedExtIEs() ProSeAuthorizedExtIETable { return ProSeAuthorizedExtIETable{} }

// ID returns the ASN.1 object-set identity of ProSeAuthorizedExtIETable.
func (ProSeAuthorizedExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ProSeAuthorizedExtIETable.
func (ProSeAuthorizedExtIETable) Table() s00.ProSeAuthorizedExtIEsValueExtensionTable {
	return func() s00.ProSeAuthorizedExtIEsValueExtensionTable {
		sealed := s00.ProSeAuthorizedExtIEsValueExtensionTable{}
		*s00.BridgeProSeAuthorizedExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ProSeAuthorizedExtIETable) infoProSeUEtoNetworkRelaying() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ProSeAuthorizedExtIEs().ID(), ID: s00.ProtocolExtensionID(216), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeUEtoNetworkRelaying"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized-ExtIEs", Row: "id-ProSeUEtoNetworkRelaying"}}}
}

// ProSeUEtoNetworkRelaying returns the typed binding for the ProSeUEtoNetworkRelaying row of ProSeAuthorizedExtIETable.
func (t ProSeAuthorizedExtIETable) ProSeUEtoNetworkRelaying() ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding {
	return ProSeAuthorizedExtIEsProSeUEtoNetworkRelayingExtBinding{info: t.infoProSeUEtoNetworkRelaying(), codec: func() s01.ProSeUEtoNetworkRelayingValueCodec {
		sealed := s01.ProSeUEtoNetworkRelayingValueCodec{}
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldPath(&sealed) = "ProSeUEtoNetworkRelaying"
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProSeUEtoNetworkRelaying, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ProSeUEtoNetworkRelaying
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeUEtoNetworkRelaying")
			var zero s06.ProSeAuthorizedExtIEsValue
			decoded, err := s06.BridgeProSeAuthorizedExtIEsValueMethodDecode(zero, s00.ProtocolIEID(216), raw)
			if err != nil {
				var empty s00.ProSeUEtoNetworkRelaying
				return empty, runtime.WrapDecodePath(err, "ProSeUEtoNetworkRelaying")
			}
			value, ok := decoded.AsProSeUEtoNetworkRelaying()
			if !ok {
				var empty s00.ProSeUEtoNetworkRelaying
				return empty, fmt.Errorf("binding ProSeAuthorized-ExtIEs.id-ProSeUEtoNetworkRelaying: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldEncode(&sealed) = func(value s00.ProSeUEtoNetworkRelaying, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s06.BridgeProSeAuthorizedExtIEsValueMethodEncodeFresh((func() s06.ProSeAuthorizedExtIEsValue {
				sealed := s06.ProSeAuthorizedExtIEsValue{}
				*s06.BridgeProSeAuthorizedExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(216)
				*s06.BridgeProSeAuthorizedExtIEsValueFieldRowProSeUEtoNetworkRelaying(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldCapture(&sealed) = func(v s00.ProSeUEtoNetworkRelaying, options aper.DecodeState) (s00.ProSeUEtoNetworkRelaying, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProSeUEtoNetworkRelaying(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldCompare(&sealed) = func(v s00.ProSeUEtoNetworkRelaying, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s03.BridgeCompareS1APProSeUEtoNetworkRelaying(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeProSeUEtoNetworkRelayingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeUEtoNetworkRelaying"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ProSeUEtoNetworkRelaying) s06.ProSeAuthorizedExtIEsValue {
			return func() s06.ProSeAuthorizedExtIEsValue {
				sealed := s06.ProSeAuthorizedExtIEsValue{}
				*s06.BridgeProSeAuthorizedExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(216)
				*s06.BridgeProSeAuthorizedExtIEsValueFieldRowProSeUEtoNetworkRelaying(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s06.ProSeAuthorizedExtIEsValue) (*s00.ProSeUEtoNetworkRelaying, bool) {
			return value.AsProSeUEtoNetworkRelaying()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ProSeAuthorizedExtIETable.
func (t ProSeAuthorizedExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ProSeAuthorizedExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(216):
		return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ProSeUEtoNetworkRelaying requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ProSeAuthorizedExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ProSeAuthorizedExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.ProSeAuthorizedExtIEsValue {
			sealed := s06.ProSeAuthorizedExtIEsValue{}
			*s06.BridgeProSeAuthorizedExtIEsValueFieldId(&sealed) = id
			*s06.BridgeProSeAuthorizedExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeProSeAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RATRestrictionsItemExtIETable struct{}

func RATRestrictionsItemExtIEs() RATRestrictionsItemExtIETable {
	return RATRestrictionsItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of RATRestrictionsItemExtIETable.
func (RATRestrictionsItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RAT-RestrictionsItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RATRestrictionsItemExtIETable.
func (RATRestrictionsItemExtIETable) Table() s00.RATRestrictionsItemExtIEsValueExtensionTable {
	return func() s00.RATRestrictionsItemExtIEsValueExtensionTable {
		sealed := s00.RATRestrictionsItemExtIEsValueExtensionTable{}
		*s00.BridgeRATRestrictionsItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RATRestrictionsItemExtIETable.
func (t RATRestrictionsItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RATRestrictionsItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RATRestrictionsItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RATRestrictionsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RATRestrictionsItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RATRestrictionsItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RATRestrictionsItemExtIEsValue {
			sealed := s06.RATRestrictionsItemExtIEsValue{}
			*s06.BridgeRATRestrictionsItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRATRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRATRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RIMTransferExtIETable struct{}

func RIMTransferExtIEs() RIMTransferExtIETable { return RIMTransferExtIETable{} }

// ID returns the ASN.1 object-set identity of RIMTransferExtIETable.
func (RIMTransferExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RIMTransfer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RIMTransferExtIETable.
func (RIMTransferExtIETable) Table() s00.RIMTransferExtIEsValueExtensionTable {
	return func() s00.RIMTransferExtIEsValueExtensionTable {
		sealed := s00.RIMTransferExtIEsValueExtensionTable{}
		*s00.BridgeRIMTransferExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RIMTransferExtIETable.
func (t RIMTransferExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RIMTransferExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RIMTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RIMTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RIMTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RIMTransferExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RIMTransferExtIEsValue {
			sealed := s06.RIMTransferExtIEsValue{}
			*s06.BridgeRIMTransferExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRIMTransferExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRIMTransferExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RLFReportInformationExtIETable struct{}

func RLFReportInformationExtIEs() RLFReportInformationExtIETable {
	return RLFReportInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of RLFReportInformationExtIETable.
func (RLFReportInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RLFReportInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RLFReportInformationExtIETable.
func (RLFReportInformationExtIETable) Table() s00.RLFReportInformationExtIEsValueExtensionTable {
	return func() s00.RLFReportInformationExtIEsValueExtensionTable {
		sealed := s00.RLFReportInformationExtIEsValueExtensionTable{}
		*s00.BridgeRLFReportInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RLFReportInformationExtIETable) infoNBIoTRLFReportContainer() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: RLFReportInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(313), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-RLF-Report-Container"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RLFReportInformation-ExtIEs", Row: "id-NB-IoT-RLF-Report-Container"}}}
}

// NBIoTRLFReportContainer returns the typed binding for the NBIoTRLFReportContainer row of RLFReportInformationExtIETable.
func (t RLFReportInformationExtIETable) NBIoTRLFReportContainer() RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding {
	return RLFReportInformationExtIEsNBIoTRLFReportContainerExtBinding{info: t.infoNBIoTRLFReportContainer(), codec: func() s01.NBIoTRLFReportContainerValueCodec {
		sealed := s01.NBIoTRLFReportContainerValueCodec{}
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldPath(&sealed) = "NBIoTRLFReportContainer"
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTRLFReportContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTRLFReportContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTRLFReportContainer")
			var zero s06.RLFReportInformationExtIEsValue
			decoded, err := s06.BridgeRLFReportInformationExtIEsValueMethodDecode(zero, s00.ProtocolIEID(313), raw)
			if err != nil {
				var empty s00.NBIoTRLFReportContainer
				return empty, runtime.WrapDecodePath(err, "NBIoTRLFReportContainer")
			}
			value, ok := decoded.AsNBIoTRLFReportContainer()
			if !ok {
				var empty s00.NBIoTRLFReportContainer
				return empty, fmt.Errorf("binding RLFReportInformation-ExtIEs.id-NB-IoT-RLF-Report-Container: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldEncode(&sealed) = func(value s00.NBIoTRLFReportContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s06.BridgeRLFReportInformationExtIEsValueMethodEncodeFresh((func() s06.RLFReportInformationExtIEsValue {
				sealed := s06.RLFReportInformationExtIEsValue{}
				*s06.BridgeRLFReportInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(313)
				*s06.BridgeRLFReportInformationExtIEsValueFieldRowNBIoTRLFReportContainer(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldCapture(&sealed) = func(v s00.NBIoTRLFReportContainer, options aper.DecodeState) (s00.NBIoTRLFReportContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTRLFReportContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldCompare(&sealed) = func(v s00.NBIoTRLFReportContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTRLFReportContainer(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTRLFReportContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTRLFReportContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTRLFReportContainer) s06.RLFReportInformationExtIEsValue {
			return func() s06.RLFReportInformationExtIEsValue {
				sealed := s06.RLFReportInformationExtIEsValue{}
				*s06.BridgeRLFReportInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(313)
				*s06.BridgeRLFReportInformationExtIEsValueFieldRowNBIoTRLFReportContainer(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s06.RLFReportInformationExtIEsValue) (*s00.NBIoTRLFReportContainer, bool) {
			return value.AsNBIoTRLFReportContainer()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RLFReportInformationExtIETable.
func (t RLFReportInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RLFReportInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(313):
		return RLFReportInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-NB-IoT-RLF-Report-Container requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RLFReportInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RLFReportInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RLFReportInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RLFReportInformationExtIEsValue {
			sealed := s06.RLFReportInformationExtIEsValue{}
			*s06.BridgeRLFReportInformationExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRLFReportInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRLFReportInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RecommendedCellsForPagingExtIETable struct{}

func RecommendedCellsForPagingExtIEs() RecommendedCellsForPagingExtIETable {
	return RecommendedCellsForPagingExtIETable{}
}

// ID returns the ASN.1 object-set identity of RecommendedCellsForPagingExtIETable.
func (RecommendedCellsForPagingExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellsForPaging-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RecommendedCellsForPagingExtIETable.
func (RecommendedCellsForPagingExtIETable) Table() s00.RecommendedCellsForPagingExtIEsValueExtensionTable {
	return func() s00.RecommendedCellsForPagingExtIEsValueExtensionTable {
		sealed := s00.RecommendedCellsForPagingExtIEsValueExtensionTable{}
		*s00.BridgeRecommendedCellsForPagingExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RecommendedCellsForPagingExtIETable.
func (t RecommendedCellsForPagingExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RecommendedCellsForPagingExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RecommendedCellsForPagingExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RecommendedCellsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RecommendedCellsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RecommendedCellsForPagingExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RecommendedCellsForPagingExtIEsValue {
			sealed := s06.RecommendedCellsForPagingExtIEsValue{}
			*s06.BridgeRecommendedCellsForPagingExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRecommendedCellsForPagingExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRecommendedCellsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RecommendedCellsForPagingItemExtIETable struct{}

func RecommendedCellsForPagingItemExtIEs() RecommendedCellsForPagingItemExtIETable {
	return RecommendedCellsForPagingItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of RecommendedCellsForPagingItemExtIETable.
func (RecommendedCellsForPagingItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedCellsForPagingItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RecommendedCellsForPagingItemExtIETable.
func (RecommendedCellsForPagingItemExtIETable) Table() s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable {
	return func() s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable {
		sealed := s00.RecommendedCellsForPagingItemExtIEsValueExtensionTable{}
		*s00.BridgeRecommendedCellsForPagingItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RecommendedCellsForPagingItemExtIETable.
func (t RecommendedCellsForPagingItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RecommendedCellsForPagingItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RecommendedCellsForPagingItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RecommendedCellsForPagingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RecommendedCellsForPagingItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RecommendedCellsForPagingItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RecommendedCellsForPagingItemExtIEsValue {
			sealed := s06.RecommendedCellsForPagingItemExtIEsValue{}
			*s06.BridgeRecommendedCellsForPagingItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRecommendedCellsForPagingItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRecommendedCellsForPagingItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RecommendedENBItemExtIETable struct{}

func RecommendedENBItemExtIEs() RecommendedENBItemExtIETable { return RecommendedENBItemExtIETable{} }

// ID returns the ASN.1 object-set identity of RecommendedENBItemExtIETable.
func (RecommendedENBItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedENBItem-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RecommendedENBItemExtIETable.
func (RecommendedENBItemExtIETable) Table() s00.RecommendedENBItemExtIEsValueExtensionTable {
	return func() s00.RecommendedENBItemExtIEsValueExtensionTable {
		sealed := s00.RecommendedENBItemExtIEsValueExtensionTable{}
		*s00.BridgeRecommendedENBItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RecommendedENBItemExtIETable.
func (t RecommendedENBItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RecommendedENBItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RecommendedENBItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RecommendedENBItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RecommendedENBItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RecommendedENBItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RecommendedENBItemExtIEsValue {
			sealed := s06.RecommendedENBItemExtIEsValue{}
			*s06.BridgeRecommendedENBItemExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRecommendedENBItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRecommendedENBItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RecommendedENBsForPagingExtIETable struct{}

func RecommendedENBsForPagingExtIEs() RecommendedENBsForPagingExtIETable {
	return RecommendedENBsForPagingExtIETable{}
}

// ID returns the ASN.1 object-set identity of RecommendedENBsForPagingExtIETable.
func (RecommendedENBsForPagingExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RecommendedENBsForPaging-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RecommendedENBsForPagingExtIETable.
func (RecommendedENBsForPagingExtIETable) Table() s00.RecommendedENBsForPagingExtIEsValueExtensionTable {
	return func() s00.RecommendedENBsForPagingExtIEsValueExtensionTable {
		sealed := s00.RecommendedENBsForPagingExtIEsValueExtensionTable{}
		*s00.BridgeRecommendedENBsForPagingExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RecommendedENBsForPagingExtIETable.
func (t RecommendedENBsForPagingExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RecommendedENBsForPagingExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RecommendedENBsForPagingExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RecommendedENBsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RecommendedENBsForPagingExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RecommendedENBsForPagingExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s06.RecommendedENBsForPagingExtIEsValue {
			sealed := s06.RecommendedENBsForPagingExtIEsValue{}
			*s06.BridgeRecommendedENBsForPagingExtIEsValueFieldId(&sealed) = id
			*s06.BridgeRecommendedENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaque
			*s06.BridgeRecommendedENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type RequestTypeExtIETable struct{}

func RequestTypeExtIEs() RequestTypeExtIETable { return RequestTypeExtIETable{} }

// ID returns the ASN.1 object-set identity of RequestTypeExtIETable.
func (RequestTypeExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RequestTypeExtIETable.
func (RequestTypeExtIETable) Table() s00.RequestTypeExtIEsValueExtensionTable {
	return func() s00.RequestTypeExtIEsValueExtensionTable {
		sealed := s00.RequestTypeExtIEsValueExtensionTable{}
		*s00.BridgeRequestTypeExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RequestTypeExtIETable) infoRequestTypeAdditionalInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: RequestTypeExtIEs().ID(), ID: s00.ProtocolExtensionID(298), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestTypeAdditionalInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType-ExtIEs", Row: "id-RequestTypeAdditionalInfo"}}}
}

// RequestTypeAdditionalInfo returns the typed binding for the RequestTypeAdditionalInfo row of RequestTypeExtIETable.
func (t RequestTypeExtIETable) RequestTypeAdditionalInfo() RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding {
	return RequestTypeExtIEsRequestTypeAdditionalInfoExtBinding{info: t.infoRequestTypeAdditionalInfo(), codec: func() s02.RequestTypeAdditionalInfoValueCodec {
		sealed := s02.RequestTypeAdditionalInfoValueCodec{}
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldPath(&sealed) = "RequestTypeAdditionalInfo"
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RequestTypeAdditionalInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RequestTypeAdditionalInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RequestTypeAdditionalInfo")
			var zero s08.RequestTypeExtIEsValue
			decoded, err := s08.BridgeRequestTypeExtIEsValueMethodDecode(zero, s00.ProtocolIEID(298), raw)
			if err != nil {
				var empty s00.RequestTypeAdditionalInfo
				return empty, runtime.WrapDecodePath(err, "RequestTypeAdditionalInfo")
			}
			value, ok := decoded.AsRequestTypeAdditionalInfo()
			if !ok {
				var empty s00.RequestTypeAdditionalInfo
				return empty, fmt.Errorf("binding RequestType-ExtIEs.id-RequestTypeAdditionalInfo: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldEncode(&sealed) = func(value s00.RequestTypeAdditionalInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s08.BridgeRequestTypeExtIEsValueMethodEncodeFresh((func() s08.RequestTypeExtIEsValue {
				sealed := s08.RequestTypeExtIEsValue{}
				*s08.BridgeRequestTypeExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(298)
				*s08.BridgeRequestTypeExtIEsValueFieldRowRequestTypeAdditionalInfo(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldCapture(&sealed) = func(v s00.RequestTypeAdditionalInfo, options aper.DecodeState) (s00.RequestTypeAdditionalInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRequestTypeAdditionalInfo(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldCompare(&sealed) = func(v s00.RequestTypeAdditionalInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRequestTypeAdditionalInfo(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeRequestTypeAdditionalInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestTypeAdditionalInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RequestTypeAdditionalInfo) s08.RequestTypeExtIEsValue {
			return func() s08.RequestTypeExtIEsValue {
				sealed := s08.RequestTypeExtIEsValue{}
				*s08.BridgeRequestTypeExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(298)
				*s08.BridgeRequestTypeExtIEsValueFieldRowRequestTypeAdditionalInfo(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s08.RequestTypeExtIEsValue) (*s00.RequestTypeAdditionalInfo, bool) {
			return value.AsRequestTypeAdditionalInfo()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RequestTypeExtIETable.
func (t RequestTypeExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (RequestTypeExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RequestTypeExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(298):
		return RequestTypeExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-RequestTypeAdditionalInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RequestTypeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RequestTypeExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return RequestTypeExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s08.RequestTypeExtIEsValue {
			sealed := s08.RequestTypeExtIEsValue{}
			*s08.BridgeRequestTypeExtIEsValueFieldId(&sealed) = id
			*s08.BridgeRequestTypeExtIEsValueFieldOpaque(&sealed) = opaque
			*s08.BridgeRequestTypeExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type MMECPRelocationIndicationIETable struct{}

func MMECPRelocationIndicationIEs() MMECPRelocationIndicationIETable {
	return MMECPRelocationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of MMECPRelocationIndicationIETable.
func (MMECPRelocationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMECPRelocationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMECPRelocationIndicationIETable.
func (MMECPRelocationIndicationIETable) Table() s00.MMECPRelocationIndicationIEValueIETable {
	return func() s00.MMECPRelocationIndicationIEValueIETable {
		sealed := s00.MMECPRelocationIndicationIEValueIETable{}
		*s00.BridgeMMECPRelocationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMECPRelocationIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMECPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMECPRelocationIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of MMECPRelocationIndicationIETable.
func (t MMECPRelocationIndicationIETable) MMEUES1APID() MMECPRelocationIndicationMMEUES1APIDIEBinding {
	return MMECPRelocationIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero s11.MMECPRelocationIndicationIEValue
			decoded, err := s11.BridgeMMECPRelocationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding MMECPRelocationIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s11.BridgeMMECPRelocationIndicationIEValueMethodEncodeFresh((func() s11.MMECPRelocationIndicationIEValue {
				sealed := s11.MMECPRelocationIndicationIEValue{}
				*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s11.BridgeMMECPRelocationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
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
	}(),
		inject: func(value s00.MMEUES1APID) s11.MMECPRelocationIndicationIEValue {
			return func() s11.MMECPRelocationIndicationIEValue {
				sealed := s11.MMECPRelocationIndicationIEValue{}
				*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s11.BridgeMMECPRelocationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s11.MMECPRelocationIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (MMECPRelocationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMECPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMECPRelocationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of MMECPRelocationIndicationIETable.
func (t MMECPRelocationIndicationIETable) ENBUES1APID() s11.MMECPRelocationIndicationENBUES1APIDIEBinding {
	return func() s11.MMECPRelocationIndicationENBUES1APIDIEBinding {
		sealed := s11.MMECPRelocationIndicationENBUES1APIDIEBinding{}
		*s11.BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s11.BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s11.MMECPRelocationIndicationIEValue
				decoded, err := s11.BridgeMMECPRelocationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding MMECPRelocationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s11.BridgeMMECPRelocationIndicationIEValueMethodEncodeFresh((func() s11.MMECPRelocationIndicationIEValue {
					sealed := s11.MMECPRelocationIndicationIEValue{}
					*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s11.BridgeMMECPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s11.BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s11.MMECPRelocationIndicationIEValue {
			return func() s11.MMECPRelocationIndicationIEValue {
				sealed := s11.MMECPRelocationIndicationIEValue{}
				*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s11.BridgeMMECPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s11.BridgeMMECPRelocationIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s11.MMECPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMECPRelocationIndicationIETable.
func (t MMECPRelocationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s11.MMECPRelocationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s11.MMECPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s11.MMECPRelocationIndicationIEField{Id: id, Criticality: criticality, Value: func() s11.MMECPRelocationIndicationIEValue {
			sealed := s11.MMECPRelocationIndicationIEValue{}
			*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = id
			*s11.BridgeMMECPRelocationIndicationIEValueFieldOpaque(&sealed) = opaque
			*s11.BridgeMMECPRelocationIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type NASDeliveryIndicationIETable struct{}

func NASDeliveryIndicationIEs() NASDeliveryIndicationIETable { return NASDeliveryIndicationIETable{} }

// ID returns the ASN.1 object-set identity of NASDeliveryIndicationIETable.
func (NASDeliveryIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASDeliveryIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NASDeliveryIndicationIETable.
func (NASDeliveryIndicationIETable) Table() s00.NASDeliveryIndicationIEValueIETable {
	return func() s00.NASDeliveryIndicationIEValueIETable {
		sealed := s00.NASDeliveryIndicationIEValueIETable{}
		*s00.BridgeNASDeliveryIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (NASDeliveryIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: NASDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASDeliveryIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of NASDeliveryIndicationIETable.
func (t NASDeliveryIndicationIETable) MMEUES1APID() NASDeliveryIndicationMMEUES1APIDIEBinding {
	return NASDeliveryIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero NASDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding NASDeliveryIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASDeliveryIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) NASDeliveryIndicationIEValue {
			return NASDeliveryIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *NASDeliveryIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (NASDeliveryIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: NASDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASDeliveryIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of NASDeliveryIndicationIETable.
func (t NASDeliveryIndicationIETable) ENBUES1APID() NASDeliveryIndicationENBUES1APIDIEBinding {
	return NASDeliveryIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero NASDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding NASDeliveryIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASDeliveryIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) NASDeliveryIndicationIEValue {
			return NASDeliveryIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *NASDeliveryIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NASDeliveryIndicationIETable.
func (t NASDeliveryIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (NASDeliveryIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return NASDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NASDeliveryIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return NASDeliveryIndicationIEField{Id: id, Criticality: criticality, Value: NASDeliveryIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// NBIoTRLFReportContainerCodec binds the complete APER value type.
func NBIoTRLFReportContainerCodec() s01.NBIoTRLFReportContainerValueCodec {
	return RLFReportInformationExtIEs().NBIoTRLFReportContainer().Codec()
}

// NumberOfBroadcastsCodec binds the complete source value type.
func NumberOfBroadcastsCodec() s01.NumberOfBroadcastsValueCodec {
	return func() s01.NumberOfBroadcastsValueCodec {
		sealed := s01.NumberOfBroadcastsValueCodec{}
		*s01.BridgeNumberOfBroadcastsValueCodecFieldPath(&sealed) = "NumberOfBroadcasts"
		*s01.BridgeNumberOfBroadcastsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfBroadcasts, error) {
			var zero s00.NumberOfBroadcasts
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NumberOfBroadcasts, error) {
				var v struct{ Value s00.NumberOfBroadcasts }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NumberOfBroadcasts(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfBroadcasts"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNumberOfBroadcastsValueCodecFieldEncode(&sealed) = func(value s00.NumberOfBroadcasts, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NumberOfBroadcasts, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NumberOfBroadcasts }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
		*s01.BridgeNumberOfBroadcastsValueCodecFieldCapture(&sealed) = func(v s00.NumberOfBroadcasts, options aper.DecodeState) (s00.NumberOfBroadcasts, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNumberOfBroadcasts(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeNumberOfBroadcastsValueCodecFieldCompare(&sealed) = func(v s00.NumberOfBroadcasts, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNumberOfBroadcasts(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNumberOfBroadcastsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfBroadcasts"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PDCPSNCodec binds the complete source value type.
func PDCPSNCodec() s01.PDCPSNValueCodec {
	return func() s01.PDCPSNValueCodec {
		sealed := s01.PDCPSNValueCodec{}
		*s01.BridgePDCPSNValueCodecFieldPath(&sealed) = "PDCPSN"
		*s01.BridgePDCPSNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PDCPSN, error) {
			var zero s00.PDCPSN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PDCPSN, error) {
				var v struct{ Value s00.PDCPSN }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PDCPSN(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PDCPSN"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePDCPSNValueCodecFieldEncode(&sealed) = func(value s00.PDCPSN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PDCPSN, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PDCPSN }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false); err != nil {
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
		*s01.BridgePDCPSNValueCodecFieldCapture(&sealed) = func(v s00.PDCPSN, options aper.DecodeState) (s00.PDCPSN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APPDCPSN(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePDCPSNValueCodecFieldCompare(&sealed) = func(v s00.PDCPSN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPDCPSN(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePDCPSNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PDCPSN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PDCPSNExtendedCodec binds the complete source value type.
func PDCPSNExtendedCodec() s01.PDCPSNExtendedValueCodec {
	return func() s01.PDCPSNExtendedValueCodec {
		sealed := s01.PDCPSNExtendedValueCodec{}
		*s01.BridgePDCPSNExtendedValueCodecFieldPath(&sealed) = "PDCPSNExtended"
		*s01.BridgePDCPSNExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PDCPSNExtended, error) {
			var zero s00.PDCPSNExtended
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PDCPSNExtended, error) {
				var v struct{ Value s00.PDCPSNExtended }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(32767), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PDCPSNExtended(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PDCPSNExtended"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePDCPSNExtendedValueCodecFieldEncode(&sealed) = func(value s00.PDCPSNExtended, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PDCPSNExtended, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PDCPSNExtended }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(32767), false); err != nil {
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
		*s01.BridgePDCPSNExtendedValueCodecFieldCapture(&sealed) = func(v s00.PDCPSNExtended, options aper.DecodeState) (s00.PDCPSNExtended, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPDCPSNExtended(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePDCPSNExtendedValueCodecFieldCompare(&sealed) = func(v s00.PDCPSNExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPDCPSNExtended(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePDCPSNExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PDCPSNExtended"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PDCPSNlength18Codec binds the complete source value type.
func PDCPSNlength18Codec() s01.PDCPSNlength18ValueCodec {
	return func() s01.PDCPSNlength18ValueCodec {
		sealed := s01.PDCPSNlength18ValueCodec{}
		*s01.BridgePDCPSNlength18ValueCodecFieldPath(&sealed) = "PDCPSNlength18"
		*s01.BridgePDCPSNlength18ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PDCPSNlength18, error) {
			var zero s00.PDCPSNlength18
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PDCPSNlength18, error) {
				var v struct{ Value s00.PDCPSNlength18 }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(262143), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PDCPSNlength18(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PDCPSNlength18"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePDCPSNlength18ValueCodecFieldEncode(&sealed) = func(value s00.PDCPSNlength18, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PDCPSNlength18, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PDCPSNlength18 }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(262143), false); err != nil {
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
		*s01.BridgePDCPSNlength18ValueCodecFieldCapture(&sealed) = func(v s00.PDCPSNlength18, options aper.DecodeState) (s00.PDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePDCPSNlength18ValueCodecFieldCompare(&sealed) = func(v s00.PDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPDCPSNlength18(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePDCPSNlength18ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PacketLossRateCodec binds the complete APER value type.
func PacketLossRateCodec() s01.PacketLossRateValueCodec {
	return s10.ERABQoSParametersExtIEs().DownlinkPacketLossRate().Codec()
}

// PriorityLevelCodec binds the complete source value type.
func PriorityLevelCodec() s01.PriorityLevelValueCodec {
	return func() s01.PriorityLevelValueCodec {
		sealed := s01.PriorityLevelValueCodec{}
		*s01.BridgePriorityLevelValueCodecFieldPath(&sealed) = "PriorityLevel"
		*s01.BridgePriorityLevelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PriorityLevel, error) {
			var zero s00.PriorityLevel
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PriorityLevel, error) {
				var v struct{ Value s00.PriorityLevel }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(15), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PriorityLevel(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PriorityLevel"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePriorityLevelValueCodecFieldEncode(&sealed) = func(value s00.PriorityLevel, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PriorityLevel, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PriorityLevel }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(15), false); err != nil {
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
		*s01.BridgePriorityLevelValueCodecFieldCapture(&sealed) = func(v s00.PriorityLevel, options aper.DecodeState) (s00.PriorityLevel, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPriorityLevel(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePriorityLevelValueCodecFieldCompare(&sealed) = func(v s00.PriorityLevel, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPriorityLevel(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s01.BridgePriorityLevelValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PriorityLevel"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProSeUEtoNetworkRelayingCodec binds the complete APER value type.
func ProSeUEtoNetworkRelayingCodec() s01.ProSeUEtoNetworkRelayingValueCodec {
	return ProSeAuthorizedExtIEs().ProSeUEtoNetworkRelaying().Codec()
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
			value, err := (func(bb *aper.BitBuffer) (s00.ProcedureCode, error) {
				var v struct{ Value s00.ProcedureCode }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ProcedureCode(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProcedureCode"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeProcedureCodeValueCodecFieldEncode(&sealed) = func(value s00.ProcedureCode, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ProcedureCode, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ProcedureCode }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
		*s01.BridgeProcedureCodeValueCodecFieldCapture(&sealed) = func(v s00.ProcedureCode, options aper.DecodeState) (s00.ProcedureCode, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProcedureCode(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProcedureCodeValueCodecFieldCompare(&sealed) = func(v s00.ProcedureCode, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s03.BridgeCompareS1APProcedureCode(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s01.BridgeProcedureCodeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProcedureCode"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProtocolExtensionIDCodec binds the complete source value type.
func ProtocolExtensionIDCodec() s01.ProtocolExtensionIDValueCodec {
	return func() s01.ProtocolExtensionIDValueCodec {
		sealed := s01.ProtocolExtensionIDValueCodec{}
		*s01.BridgeProtocolExtensionIDValueCodecFieldPath(&sealed) = "ProtocolExtensionID"
		*s01.BridgeProtocolExtensionIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProtocolExtensionID, error) {
			var zero s00.ProtocolExtensionID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ProtocolExtensionID, error) {
				var v struct{ Value s00.ProtocolExtensionID }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ProtocolExtensionID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeProtocolExtensionIDValueCodecFieldEncode(&sealed) = func(value s00.ProtocolExtensionID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ProtocolExtensionID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ProtocolExtensionID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
		*s01.BridgeProtocolExtensionIDValueCodecFieldCapture(&sealed) = func(v s00.ProtocolExtensionID, options aper.DecodeState) (s00.ProtocolExtensionID, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProtocolExtensionID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProtocolExtensionIDValueCodecFieldCompare(&sealed) = func(v s00.ProtocolExtensionID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s03.BridgeCompareS1APProtocolExtensionID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeProtocolExtensionIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
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
			value, err := (func(bb *aper.BitBuffer) (s00.ProtocolIEID, error) {
				var v struct{ Value s00.ProtocolIEID }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ProtocolIEID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeProtocolIEIDValueCodecFieldEncode(&sealed) = func(value s00.ProtocolIEID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ProtocolIEID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ProtocolIEID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
		*s01.BridgeProtocolIEIDValueCodecFieldCapture(&sealed) = func(v s00.ProtocolIEID, options aper.DecodeState) (s00.ProtocolIEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProtocolIEID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProtocolIEIDValueCodecFieldCompare(&sealed) = func(v s00.ProtocolIEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s03.BridgeCompareS1APProtocolIEID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeProtocolIEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// QCICodec binds the complete source value type.
func QCICodec() s01.QCIValueCodec {
	return func() s01.QCIValueCodec {
		sealed := s01.QCIValueCodec{}
		*s01.BridgeQCIValueCodecFieldPath(&sealed) = "QCI"
		*s01.BridgeQCIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.QCI, error) {
			var zero s00.QCI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.QCI, error) {
				var v struct{ Value s00.QCI }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.QCI(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "QCI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeQCIValueCodecFieldEncode(&sealed) = func(value s00.QCI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.QCI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.QCI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
		*s01.BridgeQCIValueCodecFieldCapture(&sealed) = func(v s00.QCI, options aper.DecodeState) (s00.QCI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APQCI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s01.BridgeQCIValueCodecFieldCompare(&sealed) = func(v s00.QCI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APQCI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeQCIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:QCI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RANUENGAPIDCodec binds the complete source value type.
func RANUENGAPIDCodec() s01.RANUENGAPIDValueCodec {
	return func() s01.RANUENGAPIDValueCodec {
		sealed := s01.RANUENGAPIDValueCodec{}
		*s01.BridgeRANUENGAPIDValueCodecFieldPath(&sealed) = "RANUENGAPID"
		*s01.BridgeRANUENGAPIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RANUENGAPID, error) {
			var zero s00.RANUENGAPID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.RANUENGAPID, error) {
				var v struct{ Value s00.RANUENGAPID }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.RANUENGAPID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RANUENGAPID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRANUENGAPIDValueCodecFieldEncode(&sealed) = func(value s00.RANUENGAPID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.RANUENGAPID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.RANUENGAPID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		*s01.BridgeRANUENGAPIDValueCodecFieldCapture(&sealed) = func(v s00.RANUENGAPID, options aper.DecodeState) (s00.RANUENGAPID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRANUENGAPID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRANUENGAPIDValueCodecFieldCompare(&sealed) = func(v s00.RANUENGAPID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRANUENGAPID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeRANUENGAPIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RANUENGAPID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RNCIDCodec binds the complete source value type.
func RNCIDCodec() s01.RNCIDValueCodec {
	return func() s01.RNCIDValueCodec {
		sealed := s01.RNCIDValueCodec{}
		*s01.BridgeRNCIDValueCodecFieldPath(&sealed) = "RNCID"
		*s01.BridgeRNCIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RNCID, error) {
			var zero s00.RNCID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.RNCID, error) {
				var v struct{ Value s00.RNCID }
				err := func() error {
					val_value, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.RNCID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "RNCID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeRNCIDValueCodecFieldEncode(&sealed) = func(value s00.RNCID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.RNCID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.RNCID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerAligned(bb, int64(v.Value), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false); err != nil {
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
		*s01.BridgeRNCIDValueCodecFieldCapture(&sealed) = func(v s00.RNCID, options aper.DecodeState) (s00.RNCID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRNCID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeRNCIDValueCodecFieldCompare(&sealed) = func(v s00.RNCID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRNCID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRNCIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RNCID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RequestTypeAdditionalInfoCodec binds the complete APER value type.
func RequestTypeAdditionalInfoCodec() s02.RequestTypeAdditionalInfoValueCodec {
	return RequestTypeExtIEs().RequestTypeAdditionalInfo().Codec()
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCapture(v *MMECPRelocationIndicationIEContainerValueCodec) *func(s11.MMECPRelocationIndicationIEContainer, aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCompare(v *MMECPRelocationIndicationIEContainerValueCodec) *func(s11.MMECPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldContext(v *MMECPRelocationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(v *MMECPRelocationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(v *MMECPRelocationIndicationIEContainerValueCodec) *func(s11.MMECPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationIEContainerValueCodecFieldPath(v *MMECPRelocationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCapture(v *MMECPRelocationIndicationIEFieldValueCodec) *func(s11.MMECPRelocationIndicationIEField, aper.DecodeState) (s11.MMECPRelocationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCompare(v *MMECPRelocationIndicationIEFieldValueCodec) *func(s11.MMECPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldContext(v *MMECPRelocationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldDecode(v *MMECPRelocationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (s11.MMECPRelocationIndicationIEField, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldEncode(v *MMECPRelocationIndicationIEFieldValueCodec) *func(s11.MMECPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationIEFieldValueCodecFieldPath(v *MMECPRelocationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *MMECPRelocationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMECPRelocationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(MMECPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEContainer, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEContainer, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldReplay(v *MeasurementThresholdL1LoggedMDTExtIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldWithoutReplay(v *MeasurementThresholdL1LoggedMDTExtIEField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(v *MeasurementThresholdL1LoggedMDTExtIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(v *MeasurementThresholdL1LoggedMDTExtIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEField, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEField, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *func(MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCapture(v *MutingPatternInformationExtIEsExtContainerValueCodec) *func(MutingPatternInformationExtIEsExtContainer, aper.DecodeState) (MutingPatternInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCompare(v *MutingPatternInformationExtIEsExtContainerValueCodec) *func(MutingPatternInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldContext(v *MutingPatternInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldDecode(v *MutingPatternInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (MutingPatternInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldEncode(v *MutingPatternInformationExtIEsExtContainerValueCodec) *func(MutingPatternInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldPath(v *MutingPatternInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMutingPatternInformationExtIEsExtFieldFieldReplay(v *MutingPatternInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeMutingPatternInformationExtIEsExtFieldFieldWithoutReplay(v *MutingPatternInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(v *MutingPatternInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *MutingPatternInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCapture(v *MutingPatternInformationExtIEsExtFieldValueCodec) *func(MutingPatternInformationExtIEsExtField, aper.DecodeState) (MutingPatternInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCompare(v *MutingPatternInformationExtIEsExtFieldValueCodec) *func(MutingPatternInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldContext(v *MutingPatternInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldDecode(v *MutingPatternInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (MutingPatternInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldEncode(v *MutingPatternInformationExtIEsExtFieldValueCodec) *func(MutingPatternInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldPath(v *MutingPatternInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldCapture(v *NASDeliveryIndicationIEContainerValueCodec) *func(NASDeliveryIndicationIEContainer, aper.DecodeState) (NASDeliveryIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldCompare(v *NASDeliveryIndicationIEContainerValueCodec) *func(NASDeliveryIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldContext(v *NASDeliveryIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(v *NASDeliveryIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndicationIEContainer, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(v *NASDeliveryIndicationIEContainerValueCodec) *func(NASDeliveryIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationIEContainerValueCodecFieldPath(v *NASDeliveryIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationIEFieldFieldReplay(v *NASDeliveryIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeNASDeliveryIndicationIEFieldFieldWithoutReplay(v *NASDeliveryIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(v *NASDeliveryIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(v *NASDeliveryIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldCapture(v *NASDeliveryIndicationIEFieldValueCodec) *func(NASDeliveryIndicationIEField, aper.DecodeState) (NASDeliveryIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldCompare(v *NASDeliveryIndicationIEFieldValueCodec) *func(NASDeliveryIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldContext(v *NASDeliveryIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldDecode(v *NASDeliveryIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndicationIEField, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldEncode(v *NASDeliveryIndicationIEFieldValueCodec) *func(NASDeliveryIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationIEFieldValueCodecFieldPath(v *NASDeliveryIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueERABIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldPath(v *NASDeliveryIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationIEValueFieldId(v *NASDeliveryIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeNASDeliveryIndicationIEValueFieldIsOpaque(v *NASDeliveryIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeNASDeliveryIndicationIEValueFieldOpaque(v *NASDeliveryIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeNASDeliveryIndicationIEValueFieldRowENBUES1APID(v *NASDeliveryIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeNASDeliveryIndicationIEValueFieldRowMMEUES1APID(v *NASDeliveryIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeNASDeliveryIndicationIEValueMethodCaptureSemantics(v NASDeliveryIndicationIEValue, a0 aper.SemanticCapture) NASDeliveryIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeNASDeliveryIndicationIEValueMethodCompareSemantics(v NASDeliveryIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeNASDeliveryIndicationIEValueMethodMatchesID(v NASDeliveryIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeNASDeliveryIndicationIEValueMethodRule(v NASDeliveryIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolIEContainerList, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASDeliveryIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtContainer, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldPath(v *NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldReplay(v *NBIoTPagingEDRXInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v *NBIoTPagingEDRXInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(v *NBIoTPagingEDRXInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *NBIoTPagingEDRXInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtField, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *func(NBIoTPagingEDRXInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldPath(v *NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldCapture(v *NGENBExtIEsExtContainerValueCodec) *func(NGENBExtIEsExtContainer, aper.DecodeState) (NGENBExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldCompare(v *NGENBExtIEsExtContainerValueCodec) *func(NGENBExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldContext(v *NGENBExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldDecode(v *NGENBExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NGENBExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldEncode(v *NGENBExtIEsExtContainerValueCodec) *func(NGENBExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNGENBExtIEsExtContainerValueCodecFieldPath(v *NGENBExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNGENBExtIEsExtFieldFieldReplay(v *NGENBExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeNGENBExtIEsExtFieldFieldWithoutReplay(v *NGENBExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(v *NGENBExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(v *NGENBExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldCapture(v *NGENBExtIEsExtFieldValueCodec) *func(NGENBExtIEsExtField, aper.DecodeState) (NGENBExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldCompare(v *NGENBExtIEsExtFieldValueCodec) *func(NGENBExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldContext(v *NGENBExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldDecode(v *NGENBExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NGENBExtIEsExtField, error) {
	return &v.decode
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldEncode(v *NGENBExtIEsExtFieldValueCodec) *func(NGENBExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNGENBExtIEsExtFieldValueCodecFieldPath(v *NGENBExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldCapture(v *NRCGIExtIEsExtContainerValueCodec) *func(NRCGIExtIEsExtContainer, aper.DecodeState) (NRCGIExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldCompare(v *NRCGIExtIEsExtContainerValueCodec) *func(NRCGIExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldContext(v *NRCGIExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldDecode(v *NRCGIExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NRCGIExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldEncode(v *NRCGIExtIEsExtContainerValueCodec) *func(NRCGIExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCGIExtIEsExtContainerValueCodecFieldPath(v *NRCGIExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRCGIExtIEsExtFieldFieldReplay(v *NRCGIExtIEsExtField) *aper.Snapshot { return &v.replay }
func BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v *NRCGIExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(v *NRCGIExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRCGIExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldCapture(v *NRCGIExtIEsExtFieldValueCodec) *func(NRCGIExtIEsExtField, aper.DecodeState) (NRCGIExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldCompare(v *NRCGIExtIEsExtFieldValueCodec) *func(NRCGIExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldContext(v *NRCGIExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldDecode(v *NRCGIExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NRCGIExtIEsExtField, error) {
	return &v.decode
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldEncode(v *NRCGIExtIEsExtFieldValueCodec) *func(NRCGIExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCGIExtIEsExtFieldValueCodecFieldPath(v *NRCGIExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtContainer, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldPath(v *NRUESecurityCapabilitiesExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v *NRUESecurityCapabilitiesExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v *NRUESecurityCapabilitiesExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(v *NRUESecurityCapabilitiesExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRUESecurityCapabilitiesExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtField, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NRUESecurityCapabilitiesExtIEsExtField, error) {
	return &v.decode
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *func(NRUESecurityCapabilitiesExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldPath(v *NRUESecurityCapabilitiesExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCapture(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCompare(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldContext(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldDecode(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldEncode(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldPath(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldReplay(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldWithoutReplay(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCapture(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCompare(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldContext(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldDecode(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrateExtIEsExtField, error) {
	return &v.decode
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldEncode(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *func(NRUESidelinkAggregateMaximumBitrateExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldPath(v *NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCapture(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtContainer, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCompare(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldContext(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldDecode(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldEncode(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldPath(v *NRV2XServicesAuthorizedExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v *NRV2XServicesAuthorizedExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v *NRV2XServicesAuthorizedExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(v *NRV2XServicesAuthorizedExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(v *NRV2XServicesAuthorizedExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCapture(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtField, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCompare(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldContext(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldDecode(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (NRV2XServicesAuthorizedExtIEsExtField, error) {
	return &v.decode
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldEncode(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *func(NRV2XServicesAuthorizedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldPath(v *NRV2XServicesAuthorizedExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCapture(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *func(PC5FlowBitRatesExtIEsExtContainer, aper.DecodeState) (PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCompare(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *func(PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldContext(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldDecode(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PC5FlowBitRatesExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldEncode(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *func(PC5FlowBitRatesExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldPath(v *PC5FlowBitRatesExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5FlowBitRatesExtIEsExtFieldFieldReplay(v *PC5FlowBitRatesExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePC5FlowBitRatesExtIEsExtFieldFieldWithoutReplay(v *PC5FlowBitRatesExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(v *PC5FlowBitRatesExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(v *PC5FlowBitRatesExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCapture(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *func(PC5FlowBitRatesExtIEsExtField, aper.DecodeState) (PC5FlowBitRatesExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCompare(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *func(PC5FlowBitRatesExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldContext(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldDecode(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PC5FlowBitRatesExtIEsExtField, error) {
	return &v.decode
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldEncode(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *func(PC5FlowBitRatesExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldPath(v *PC5FlowBitRatesExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCapture(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *func(PC5QoSFlowItemExtIEsExtContainer, aper.DecodeState) (PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCompare(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *func(PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldContext(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldDecode(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PC5QoSFlowItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldEncode(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *func(PC5QoSFlowItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldPath(v *PC5QoSFlowItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSFlowItemExtIEsExtFieldFieldReplay(v *PC5QoSFlowItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSFlowItemExtIEsExtFieldFieldWithoutReplay(v *PC5QoSFlowItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(v *PC5QoSFlowItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *PC5QoSFlowItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCapture(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *func(PC5QoSFlowItemExtIEsExtField, aper.DecodeState) (PC5QoSFlowItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCompare(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *func(PC5QoSFlowItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldContext(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldDecode(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PC5QoSFlowItemExtIEsExtField, error) {
	return &v.decode
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldEncode(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *func(PC5QoSFlowItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldPath(v *PC5QoSFlowItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCapture(v *PC5QoSParametersExtIEsExtContainerValueCodec) *func(PC5QoSParametersExtIEsExtContainer, aper.DecodeState) (PC5QoSParametersExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCompare(v *PC5QoSParametersExtIEsExtContainerValueCodec) *func(PC5QoSParametersExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldContext(v *PC5QoSParametersExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldDecode(v *PC5QoSParametersExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PC5QoSParametersExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldEncode(v *PC5QoSParametersExtIEsExtContainerValueCodec) *func(PC5QoSParametersExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldPath(v *PC5QoSParametersExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v *PC5QoSParametersExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v *PC5QoSParametersExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(v *PC5QoSParametersExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(v *PC5QoSParametersExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCapture(v *PC5QoSParametersExtIEsExtFieldValueCodec) *func(PC5QoSParametersExtIEsExtField, aper.DecodeState) (PC5QoSParametersExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCompare(v *PC5QoSParametersExtIEsExtFieldValueCodec) *func(PC5QoSParametersExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldContext(v *PC5QoSParametersExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldDecode(v *PC5QoSParametersExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PC5QoSParametersExtIEsExtField, error) {
	return &v.decode
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldEncode(v *PC5QoSParametersExtIEsExtFieldValueCodec) *func(PC5QoSParametersExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldPath(v *PC5QoSParametersExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCapture(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *func(PLMNAreaBasedQMCExtIEsExtContainer, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCompare(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *func(PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldContext(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldDecode(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldEncode(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *func(PLMNAreaBasedQMCExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldPath(v *PLMNAreaBasedQMCExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v *PLMNAreaBasedQMCExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v *PLMNAreaBasedQMCExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(v *PLMNAreaBasedQMCExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(v *PLMNAreaBasedQMCExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCapture(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *func(PLMNAreaBasedQMCExtIEsExtField, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCompare(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *func(PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldContext(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldDecode(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PLMNAreaBasedQMCExtIEsExtField, error) {
	return &v.decode
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldEncode(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *func(PLMNAreaBasedQMCExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldPath(v *PLMNAreaBasedQMCExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldCapture(v *PSCellInformationExtIEsExtContainerValueCodec) *func(PSCellInformationExtIEsExtContainer, aper.DecodeState) (PSCellInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldCompare(v *PSCellInformationExtIEsExtContainerValueCodec) *func(PSCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldContext(v *PSCellInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldDecode(v *PSCellInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PSCellInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldEncode(v *PSCellInformationExtIEsExtContainerValueCodec) *func(PSCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePSCellInformationExtIEsExtContainerValueCodecFieldPath(v *PSCellInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePSCellInformationExtIEsExtFieldFieldReplay(v *PSCellInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v *PSCellInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(v *PSCellInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *PSCellInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldCapture(v *PSCellInformationExtIEsExtFieldValueCodec) *func(PSCellInformationExtIEsExtField, aper.DecodeState) (PSCellInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldCompare(v *PSCellInformationExtIEsExtFieldValueCodec) *func(PSCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldContext(v *PSCellInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldDecode(v *PSCellInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PSCellInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldEncode(v *PSCellInformationExtIEsExtFieldValueCodec) *func(PSCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePSCellInformationExtIEsExtFieldValueCodecFieldPath(v *PSCellInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCapture(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *func(PagingAttemptInformationExtIEsExtContainer, aper.DecodeState) (PagingAttemptInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCompare(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *func(PagingAttemptInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldContext(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldDecode(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PagingAttemptInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldEncode(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *func(PagingAttemptInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldPath(v *PagingAttemptInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v *PagingAttemptInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v *PagingAttemptInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(v *PagingAttemptInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *PagingAttemptInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCapture(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *func(PagingAttemptInformationExtIEsExtField, aper.DecodeState) (PagingAttemptInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCompare(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *func(PagingAttemptInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldContext(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldDecode(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PagingAttemptInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldEncode(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *func(PagingAttemptInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldPath(v *PagingAttemptInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *func(PagingEDRXInformationExtIEsExtContainer, aper.DecodeState) (PagingEDRXInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *func(PagingEDRXInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (PagingEDRXInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *func(PagingEDRXInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldPath(v *PagingEDRXInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v *PagingEDRXInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v *PagingEDRXInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(v *PagingEDRXInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *PagingEDRXInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *func(PagingEDRXInformationExtIEsExtField, aper.DecodeState) (PagingEDRXInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *func(PagingEDRXInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (PagingEDRXInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *func(PagingEDRXInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldPath(v *PagingEDRXInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCapture(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *func(ProSeAuthorizedExtIEsExtContainer, aper.DecodeState) (ProSeAuthorizedExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCompare(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *func(ProSeAuthorizedExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldContext(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldDecode(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ProSeAuthorizedExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldEncode(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *func(ProSeAuthorizedExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldPath(v *ProSeAuthorizedExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeAuthorizedExtIEsExtFieldFieldReplay(v *ProSeAuthorizedExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeProSeAuthorizedExtIEsExtFieldFieldWithoutReplay(v *ProSeAuthorizedExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(v *ProSeAuthorizedExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(v *ProSeAuthorizedExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCapture(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *func(ProSeAuthorizedExtIEsExtField, aper.DecodeState) (ProSeAuthorizedExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCompare(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *func(ProSeAuthorizedExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldContext(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldDecode(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ProSeAuthorizedExtIEsExtField, error) {
	return &v.decode
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldEncode(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *func(ProSeAuthorizedExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldPath(v *ProSeAuthorizedExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCapture(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *func(RATRestrictionsItemExtIEsExtContainer, aper.DecodeState) (RATRestrictionsItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCompare(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *func(RATRestrictionsItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldContext(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldDecode(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RATRestrictionsItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldEncode(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *func(RATRestrictionsItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldPath(v *RATRestrictionsItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRATRestrictionsItemExtIEsExtFieldFieldReplay(v *RATRestrictionsItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRATRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v *RATRestrictionsItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(v *RATRestrictionsItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *RATRestrictionsItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCapture(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *func(RATRestrictionsItemExtIEsExtField, aper.DecodeState) (RATRestrictionsItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCompare(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *func(RATRestrictionsItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldContext(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldDecode(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RATRestrictionsItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldEncode(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *func(RATRestrictionsItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldPath(v *RATRestrictionsItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldCapture(v *RIMTransferExtIEsExtContainerValueCodec) *func(RIMTransferExtIEsExtContainer, aper.DecodeState) (RIMTransferExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldCompare(v *RIMTransferExtIEsExtContainerValueCodec) *func(RIMTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldContext(v *RIMTransferExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldDecode(v *RIMTransferExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RIMTransferExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldEncode(v *RIMTransferExtIEsExtContainerValueCodec) *func(RIMTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMTransferExtIEsExtContainerValueCodecFieldPath(v *RIMTransferExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRIMTransferExtIEsExtFieldFieldReplay(v *RIMTransferExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRIMTransferExtIEsExtFieldFieldWithoutReplay(v *RIMTransferExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(v *RIMTransferExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(v *RIMTransferExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldCapture(v *RIMTransferExtIEsExtFieldValueCodec) *func(RIMTransferExtIEsExtField, aper.DecodeState) (RIMTransferExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldCompare(v *RIMTransferExtIEsExtFieldValueCodec) *func(RIMTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldContext(v *RIMTransferExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldDecode(v *RIMTransferExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RIMTransferExtIEsExtField, error) {
	return &v.decode
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldEncode(v *RIMTransferExtIEsExtFieldValueCodec) *func(RIMTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMTransferExtIEsExtFieldValueCodecFieldPath(v *RIMTransferExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCapture(v *RLFReportInformationExtIEsExtContainerValueCodec) *func(RLFReportInformationExtIEsExtContainer, aper.DecodeState) (RLFReportInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCompare(v *RLFReportInformationExtIEsExtContainerValueCodec) *func(RLFReportInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldContext(v *RLFReportInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldDecode(v *RLFReportInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RLFReportInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldEncode(v *RLFReportInformationExtIEsExtContainerValueCodec) *func(RLFReportInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldPath(v *RLFReportInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRLFReportInformationExtIEsExtFieldFieldReplay(v *RLFReportInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRLFReportInformationExtIEsExtFieldFieldWithoutReplay(v *RLFReportInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(v *RLFReportInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *RLFReportInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCapture(v *RLFReportInformationExtIEsExtFieldValueCodec) *func(RLFReportInformationExtIEsExtField, aper.DecodeState) (RLFReportInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCompare(v *RLFReportInformationExtIEsExtFieldValueCodec) *func(RLFReportInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldContext(v *RLFReportInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldDecode(v *RLFReportInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RLFReportInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldEncode(v *RLFReportInformationExtIEsExtFieldValueCodec) *func(RLFReportInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldPath(v *RLFReportInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCapture(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingExtIEsExtContainer, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldCompare(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldContext(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldDecode(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldEncode(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellsForPagingExtIEsExtContainerValueCodecFieldPath(v *RecommendedCellsForPagingExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldFieldReplay(v *RecommendedCellsForPagingExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldFieldWithoutReplay(v *RecommendedCellsForPagingExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldMethodMarshalAPERTo(v *RecommendedCellsForPagingExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(v *RecommendedCellsForPagingExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCapture(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingExtIEsExtField, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldCompare(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldContext(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldDecode(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellsForPagingExtIEsExtField, error) {
	return &v.decode
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldEncode(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellsForPagingExtIEsExtFieldValueCodecFieldPath(v *RecommendedCellsForPagingExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCapture(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtContainer, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldCompare(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldContext(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldDecode(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldEncode(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellsForPagingItemExtIEsExtContainerValueCodecFieldPath(v *RecommendedCellsForPagingItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldReplay(v *RecommendedCellsForPagingItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldFieldWithoutReplay(v *RecommendedCellsForPagingItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodMarshalAPERTo(v *RecommendedCellsForPagingItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *RecommendedCellsForPagingItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCapture(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtField, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldCompare(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldContext(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldDecode(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RecommendedCellsForPagingItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldEncode(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *func(RecommendedCellsForPagingItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedCellsForPagingItemExtIEsExtFieldValueCodecFieldPath(v *RecommendedCellsForPagingItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldCapture(v *RecommendedENBItemExtIEsExtContainerValueCodec) *func(RecommendedENBItemExtIEsExtContainer, aper.DecodeState) (RecommendedENBItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldCompare(v *RecommendedENBItemExtIEsExtContainerValueCodec) *func(RecommendedENBItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldContext(v *RecommendedENBItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldDecode(v *RecommendedENBItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedENBItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldEncode(v *RecommendedENBItemExtIEsExtContainerValueCodec) *func(RecommendedENBItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBItemExtIEsExtContainerValueCodecFieldPath(v *RecommendedENBItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBItemExtIEsExtFieldFieldReplay(v *RecommendedENBItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBItemExtIEsExtFieldFieldWithoutReplay(v *RecommendedENBItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBItemExtIEsExtFieldMethodMarshalAPERTo(v *RecommendedENBItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedENBItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *RecommendedENBItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldCapture(v *RecommendedENBItemExtIEsExtFieldValueCodec) *func(RecommendedENBItemExtIEsExtField, aper.DecodeState) (RecommendedENBItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldCompare(v *RecommendedENBItemExtIEsExtFieldValueCodec) *func(RecommendedENBItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldContext(v *RecommendedENBItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldDecode(v *RecommendedENBItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RecommendedENBItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldEncode(v *RecommendedENBItemExtIEsExtFieldValueCodec) *func(RecommendedENBItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBItemExtIEsExtFieldValueCodecFieldPath(v *RecommendedENBItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldCapture(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *func(RecommendedENBsForPagingExtIEsExtContainer, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldCompare(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *func(RecommendedENBsForPagingExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldContext(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldDecode(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldEncode(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *func(RecommendedENBsForPagingExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBsForPagingExtIEsExtContainerValueCodecFieldPath(v *RecommendedENBsForPagingExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldFieldReplay(v *RecommendedENBsForPagingExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldFieldWithoutReplay(v *RecommendedENBsForPagingExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(v *RecommendedENBsForPagingExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(v *RecommendedENBsForPagingExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldCapture(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *func(RecommendedENBsForPagingExtIEsExtField, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldCompare(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *func(RecommendedENBsForPagingExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldContext(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldDecode(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RecommendedENBsForPagingExtIEsExtField, error) {
	return &v.decode
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldEncode(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *func(RecommendedENBsForPagingExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBsForPagingExtIEsExtFieldValueCodecFieldPath(v *RecommendedENBsForPagingExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldCapture(v *RequestTypeExtIEsExtContainerValueCodec) *func(RequestTypeExtIEsExtContainer, aper.DecodeState) (RequestTypeExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldCompare(v *RequestTypeExtIEsExtContainerValueCodec) *func(RequestTypeExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldContext(v *RequestTypeExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldDecode(v *RequestTypeExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (RequestTypeExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldEncode(v *RequestTypeExtIEsExtContainerValueCodec) *func(RequestTypeExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestTypeExtIEsExtContainerValueCodecFieldPath(v *RequestTypeExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestTypeExtIEsExtFieldFieldReplay(v *RequestTypeExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestTypeExtIEsExtFieldFieldWithoutReplay(v *RequestTypeExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeRequestTypeExtIEsExtFieldMethodMarshalAPERTo(v *RequestTypeExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestTypeExtIEsExtFieldMethodUnmarshalAPERFrom(v *RequestTypeExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldCapture(v *RequestTypeExtIEsExtFieldValueCodec) *func(RequestTypeExtIEsExtField, aper.DecodeState) (RequestTypeExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldCompare(v *RequestTypeExtIEsExtFieldValueCodec) *func(RequestTypeExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldContext(v *RequestTypeExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldDecode(v *RequestTypeExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (RequestTypeExtIEsExtField, error) {
	return &v.decode
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldEncode(v *RequestTypeExtIEsExtFieldValueCodec) *func(RequestTypeExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestTypeExtIEsExtFieldValueCodecFieldPath(v *RequestTypeExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *NASDeliveryIndicationIEValue) Selected() (any, bool) {
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
