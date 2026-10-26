// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s24 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s24

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UplinkS1cdma2000tunnellingIEContainer is ProtocolIE-Container {{UplinkS1cdma2000tunnellingIEs}} of TS 36.413: a list of UplinkS1cdma2000tunnellingIEField values.
type UplinkS1cdma2000tunnellingIEContainer []UplinkS1cdma2000tunnellingIEField

// UplinkS1cdma2000tunnellingIEField is ProtocolIE-Field {{UplinkS1cdma2000tunnellingIEs}} of TS 36.413: an information element field.
type UplinkS1cdma2000tunnellingIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UplinkS1cdma2000tunnellingIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEField) WithoutReplay() UplinkS1cdma2000tunnellingIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UplinkS1cdma2000tunnellingIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UplinkS1cdma2000tunnellingIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *UplinkS1cdma2000tunnellingIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkS1cdma2000tunnellingIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UplinkS1cdma2000tunnellingIEValue

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

// TraceFailureIndicationIEContainer is ProtocolIE-Container {{TraceFailureIndicationIEs}} of TS 36.413: a list of TraceFailureIndicationIEField values.
type TraceFailureIndicationIEContainer []TraceFailureIndicationIEField

// TraceFailureIndicationIEField is ProtocolIE-Field {{TraceFailureIndicationIEs}} of TS 36.413: an information element field.
type TraceFailureIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         TraceFailureIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEField) WithoutReplay() TraceFailureIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TraceFailureIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TraceFailureIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *TraceFailureIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceFailureIndicationIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero TraceFailureIndicationIEValue

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

// UEContextModificationIndicationIEContainer is ProtocolIE-Container {{UEContextModificationIndicationIEs}} of TS 36.413: a list of UEContextModificationIndicationIEField values.
type UEContextModificationIndicationIEContainer []UEContextModificationIndicationIEField

// UEContextModificationIndicationIEField is ProtocolIE-Field {{UEContextModificationIndicationIEs}} of TS 36.413: an information element field.
type UEContextModificationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEField) WithoutReplay() UEContextModificationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *UEContextModificationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationIndicationIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UEContextModificationIndicationIEValue

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

// S1RemovalRequestIEContainer is ProtocolIE-Container {{S1RemovalRequestIEs}} of TS 36.413: a list of S1RemovalRequestIEField values.
type S1RemovalRequestIEContainer []S1RemovalRequestIEField

// S1RemovalRequestIEField is ProtocolIE-Field {{S1RemovalRequestIEs}} of TS 36.413: an information element field.
type S1RemovalRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1RemovalRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEField) WithoutReplay() S1RemovalRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1RemovalRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1RemovalRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *S1RemovalRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1RemovalRequestIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero S1RemovalRequestIEValue

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

// ERABToBeModifyItemBearerModReqExtIEsExtContainer is ProtocolExtensionContainer {{E-RABToBeModifyItemBearerModReqExtIEs}} of TS 36.413: a list of ERABToBeModifyItemBearerModReqExtIEsExtField values.
type ERABToBeModifyItemBearerModReqExtIEsExtContainer []ERABToBeModifyItemBearerModReqExtIEsExtField

// ERABToBeModifyItemBearerModReqExtIEsExtField is ProtocolExtensionField {{E-RABToBeModifyItemBearerModReqExtIEs}} of TS 36.413: an extension field.
type ERABToBeModifyItemBearerModReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeModifyItemBearerModReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtField) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifyItemBearerModReqExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABToBeModifyItemBearerModReqExtIEsValue

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

// SONInformationExtensionIESONInformationReportIEBinding binds SONInformationReport to the SONInformation-ExtensionIE object set of TS 36.413.
type SONInformationExtensionIESONInformationReportIEBinding struct {
	info   s00.FieldInfo
	codec  SONInformationReportValueCodec
	inject func(SONInformationReport,

	) SONInformationExtensionIEIEValue

	get func(*SONInformationExtensionIEIEValue,

	) (*SONInformationReport,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Codec() SONInformationReportValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONInformationExtensionIESONInformationReportIEBinding) New(value SONInformationReport,

) (SONInformationExtensionIEIEField, error) {
	if b.inject == nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	return SONInformationExtensionIEIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Get(field *SONInformationExtensionIEIEField) (*SONInformationReport,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SONInformationReportValueCodec is the concrete ValueCodec[SONInformationReport].
type SONInformationReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationReport,

		error)
	encode func(SONInformationReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationReport, aper.DecodeState,

	) (SONInformationReport, aper.Snapshot,

	)
	compare func(SONInformationReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationReportValueCodec) New(value SONInformationReport,

) (SONInformationReportAPERValue, error) {
	if c.encode == nil {
		return SONInformationReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationReportValueCodec) EncodeAPER(value SONInformationReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationReportValueCodec) encodeBudgetValue(value SONInformationReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationReportValueCodec) encodeChanged(value SONInformationReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEField is ProtocolIE-Field {{SONInformation-ExtensionIE}} of TS 36.413: an information element field.
type SONInformationExtensionIEIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SONInformationExtensionIEIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEField) WithoutReplay() SONInformationExtensionIEIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONInformationExtensionIEIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONInformationExtensionIEIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *SONInformationExtensionIEIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationExtensionIEIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero SONInformationExtensionIEIEValue

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

// ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding binds TransportInformation to the E-RABToBeModifyItemBearerModReqExtIEs object set of TS 36.413.
type ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  TransportInformationValueCodec
	inject func(TransportInformation,

	) ERABToBeModifyItemBearerModReqExtIEsValue

	get func(*ERABToBeModifyItemBearerModReqExtIEsValue,

	) (*TransportInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Codec() TransportInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) New(value TransportInformation,

) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Get(field *ERABToBeModifyItemBearerModReqExtIEsExtField) (*TransportInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TransportInformationValueCodec is the concrete ValueCodec[TransportInformation].
type TransportInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TransportInformation,

		error)
	encode func(TransportInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TransportInformation, aper.DecodeState,

	) (TransportInformation, aper.Snapshot,

	)
	compare func(TransportInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TransportInformationValueCodec) New(value TransportInformation,

) (TransportInformationAPERValue, error) {
	if c.encode == nil {
		return TransportInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TransportInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TransportInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TransportInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TransportInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TransportInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TransportInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TransportInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TransportInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TransportInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TransportInformationValueCodec) EncodeAPER(value TransportInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TransportInformationValueCodec) encodeBudgetValue(value TransportInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TransportInformationValueCodec) encodeChanged(value TransportInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestMMEUES1APIDIEBinding binds MMEUES1APID to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) s23.RerouteNASRequestIEValue

	get func(*s23.RerouteNASRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (s23.RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Get(field *s23.RerouteNASRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestSliceByteIEBinding binds []byte to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestSliceByteIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SliceByteValueCodec
	inject func([]byte,

	) s23.RerouteNASRequestIEValue

	get func(*s23.RerouteNASRequestIEValue,

	) (*[]byte,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestSliceByteIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestSliceByteIEBinding) Codec() s02.SliceByteValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestSliceByteIEBinding) New(value []byte,

) (s23.RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSliceByteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestSliceByteIEBinding) Get(field *s23.RerouteNASRequestIEField) (*[]byte,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestMMEGroupIDIEBinding binds MMEGroupID to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestMMEGroupIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEGroupIDValueCodec
	inject func(s00.MMEGroupID,

	) s23.RerouteNASRequestIEValue

	get func(*s23.RerouteNASRequestIEValue,

	) (*s00.MMEGroupID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Codec() s01.MMEGroupIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestMMEGroupIDIEBinding) New(value s00.MMEGroupID,

) (s23.RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEGroupIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Get(field *s23.RerouteNASRequestIEField) (*s00.MMEGroupID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestUEUsageTypeIEBinding binds UEUsageType to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestUEUsageTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUsageTypeValueCodec
	inject func(s00.UEUsageType,

	) s23.RerouteNASRequestIEValue

	get func(*s23.RerouteNASRequestIEValue,

	) (*s00.UEUsageType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Codec() s02.UEUsageTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestUEUsageTypeIEBinding) New(value s00.UEUsageType,

) (s23.RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUsageTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s23.RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Get(field *s23.RerouteNASRequestIEField) (*s00.UEUsageType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalRequestGlobalENBIDIEBinding binds GlobalENBID to the S1RemovalRequestIEs object set of TS 36.413.
type S1RemovalRequestGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s21.GlobalENBIDValueCodec
	inject func(s21.GlobalENBID,

	) S1RemovalRequestIEValue

	get func(*S1RemovalRequestIEValue,

	) (*s21.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Codec() s21.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1RemovalRequestGlobalENBIDIEBinding) New(value s21.GlobalENBID,

) (S1RemovalRequestIEField, error) {
	if b.inject == nil {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s21.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Get(field *S1RemovalRequestIEField) (*s21.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceFailureIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the TraceFailureIndicationIEs object set of TS 36.413.
type TraceFailureIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) TraceFailureIndicationIEValue

	get func(*TraceFailureIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (TraceFailureIndicationIEField, error) {
	if b.inject == nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Get(field *TraceFailureIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceFailureIndicationENBUES1APIDIEBinding binds ENBUES1APID to the TraceFailureIndicationIEs object set of TS 36.413.
type TraceFailureIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) TraceFailureIndicationIEValue

	get func(*TraceFailureIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceFailureIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (TraceFailureIndicationIEField, error) {
	if b.inject == nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceFailureIndicationENBUES1APIDIEBinding) Get(field *TraceFailureIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceFailureIndicationEUTRANTraceIDIEBinding binds EUTRANTraceID to the TraceFailureIndicationIEs object set of TS 36.413.
type TraceFailureIndicationEUTRANTraceIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EUTRANTraceIDValueCodec
	inject func(s00.EUTRANTraceID,

	) TraceFailureIndicationIEValue

	get func(*TraceFailureIndicationIEValue,

	) (*s00.EUTRANTraceID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationEUTRANTraceIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationEUTRANTraceIDIEBinding) Codec() s00.EUTRANTraceIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceFailureIndicationEUTRANTraceIDIEBinding) New(value s00.EUTRANTraceID,

) (TraceFailureIndicationIEField, error) {
	if b.inject == nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceFailureIndicationEUTRANTraceIDIEBinding) Get(field *TraceFailureIndicationIEField) (*s00.EUTRANTraceID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceFailureIndicationCauseIEBinding binds Cause to the TraceFailureIndicationIEs object set of TS 36.413.
type TraceFailureIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) TraceFailureIndicationIEValue

	get func(*TraceFailureIndicationIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TraceFailureIndicationCauseIEBinding) New(value s17.Cause,

) (TraceFailureIndicationIEField, error) {
	if b.inject == nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceFailureIndicationCauseIEBinding) Get(field *TraceFailureIndicationIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextModificationIndicationIEs object set of TS 36.413.
type UEContextModificationIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Get(field *UEContextModificationIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationENBUES1APIDIEBinding binds ENBUES1APID to the UEContextModificationIndicationIEs object set of TS 36.413.
type UEContextModificationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Get(field *UEContextModificationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationCSGMembershipInfoIEBinding binds CSGMembershipInfo to the UEContextModificationIndicationIEs object set of TS 36.413.
type UEContextModificationIndicationCSGMembershipInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CSGMembershipInfoValueCodec
	inject func(s17.CSGMembershipInfo,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s17.CSGMembershipInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Codec() s17.CSGMembershipInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) New(value s17.CSGMembershipInfo,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCSGMembershipInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Get(field *UEContextModificationIndicationIEField) (*s17.CSGMembershipInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding binds MMEUES1APID to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingENBUES1APIDIEBinding binds ENBUES1APID to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding binds Cdma2000RATType to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000RATTypeValueCodec
	inject func(s00.Cdma2000RATType,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000RATType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Codec() s00.Cdma2000RATTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) New(value s00.Cdma2000RATType,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000RATType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding binds Cdma2000SectorID to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000SectorIDValueCodec
	inject func(s00.Cdma2000SectorID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000SectorID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Codec() s00.Cdma2000SectorIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) New(value s00.Cdma2000SectorID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000SectorIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000SectorID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding binds Cdma2000HORequiredIndication to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000HORequiredIndicationValueCodec
	inject func(s00.Cdma2000HORequiredIndication,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000HORequiredIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Codec() s00.Cdma2000HORequiredIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) New(value s00.Cdma2000HORequiredIndication,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000HORequiredIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding binds Cdma2000OneXSRVCCInfo to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s17.Cdma2000OneXSRVCCInfoValueCodec
	inject func(s17.Cdma2000OneXSRVCCInfo,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s17.Cdma2000OneXSRVCCInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Codec() s17.Cdma2000OneXSRVCCInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) New(value s17.Cdma2000OneXSRVCCInfo,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s17.Cdma2000OneXSRVCCInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding binds Cdma2000OneXRAND to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000OneXRANDValueCodec
	inject func(s00.Cdma2000OneXRAND,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000OneXRAND,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Codec() s00.Cdma2000OneXRANDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) New(value s00.Cdma2000OneXRAND,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000OneXRANDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000OneXRAND,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000PDUIEBinding binds Cdma2000PDU to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingCdma2000PDUIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000PDUValueCodec
	inject func(s00.Cdma2000PDU,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000PDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Codec() s00.Cdma2000PDUValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) New(value s00.Cdma2000PDU,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000PDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000PDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding binds EUTRANRoundTripDelayEstimationInfo to the UplinkS1cdma2000tunnellingIEs object set of TS 36.413.
type UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EUTRANRoundTripDelayEstimationInfoValueCodec
	inject func(s00.EUTRANRoundTripDelayEstimationInfo,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.EUTRANRoundTripDelayEstimationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Codec() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) New(value s00.EUTRANRoundTripDelayEstimationInfo,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.EUTRANRoundTripDelayEstimationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// FailureEventReportValueCodec is the concrete ValueCodec[FailureEventReport].
type FailureEventReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (FailureEventReport,

		error)
	encode func(FailureEventReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(FailureEventReport, aper.DecodeState,

	) (FailureEventReport, aper.Snapshot,

	)
	compare func(FailureEventReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FailureEventReportValueCodec) New(value FailureEventReport,

) (FailureEventReportAPERValue, error) {
	if c.encode == nil {
		return FailureEventReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FailureEventReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FailureEventReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FailureEventReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FailureEventReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FailureEventReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FailureEventReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FailureEventReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FailureEventReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FailureEventReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FailureEventReportValueCodec) EncodeAPER(value FailureEventReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c FailureEventReportValueCodec) encodeBudgetValue(value FailureEventReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FailureEventReportValueCodec) encodeChanged(value FailureEventReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionValueCodec is the concrete ValueCodec[SONInformationExtension].
type SONInformationExtensionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtension,

		error)
	encode func(SONInformationExtension,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtension, aper.DecodeState,

	) (SONInformationExtension, aper.Snapshot,

	)
	compare func(SONInformationExtension, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionValueCodec) New(value SONInformationExtension,

) (SONInformationExtensionAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionValueCodec) EncodeAPER(value SONInformationExtensionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionValueCodec) encodeBudgetValue(value SONInformationExtension,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionValueCodec) encodeChanged(value SONInformationExtension,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferCauseValueCodec is the concrete ValueCodec[SONtransferCause].
type SONtransferCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferCause,

		error)
	encode func(SONtransferCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferCause, aper.DecodeState,

	) (SONtransferCause, aper.Snapshot,

	)
	compare func(SONtransferCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferCauseValueCodec) New(value SONtransferCause,

) (SONtransferCauseAPERValue, error) {
	if c.encode == nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferCauseValueCodec) EncodeAPER(value SONtransferCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONtransferCauseValueCodec) encodeBudgetValue(value SONtransferCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferCauseValueCodec) encodeChanged(value SONtransferCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionValueCodec is the concrete ValueCodec[SourceNodeIDExtension].
type SourceNodeIDExtensionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtension,

		error)
	encode func(SourceNodeIDExtension,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtension, aper.DecodeState,

	) (SourceNodeIDExtension, aper.Snapshot,

	)
	compare func(SourceNodeIDExtension, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionValueCodec) New(value SourceNodeIDExtension,

) (SourceNodeIDExtensionAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionValueCodec) EncodeAPER(value SourceNodeIDExtensionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionValueCodec) encodeBudgetValue(value SourceNodeIDExtension,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionValueCodec) encodeChanged(value SourceNodeIDExtension,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TooEarlyInterRATHOReportReportFromEUTRANValueCodec is the concrete ValueCodec[TooEarlyInterRATHOReportReportFromEUTRAN].
type TooEarlyInterRATHOReportReportFromEUTRANValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TooEarlyInterRATHOReportReportFromEUTRAN,

		error)
	encode func(TooEarlyInterRATHOReportReportFromEUTRAN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TooEarlyInterRATHOReportReportFromEUTRAN, aper.DecodeState,

	) (TooEarlyInterRATHOReportReportFromEUTRAN, aper.Snapshot,

	)
	compare func(TooEarlyInterRATHOReportReportFromEUTRAN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TooEarlyInterRATHOReportReportFromEUTRANValueCodec) New(value TooEarlyInterRATHOReportReportFromEUTRAN,

) (TooEarlyInterRATHOReportReportFromEUTRANAPERValue, error) {
	if c.encode == nil {
		return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TooEarlyInterRATHOReportReportFromEUTRANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TooEarlyInterRATHOReportReportFromEUTRANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TooEarlyInterRATHOReportReportFromEUTRANAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TooEarlyInterRATHOReportReportFromEUTRANValueCodec) EncodeAPER(value TooEarlyInterRATHOReportReportFromEUTRANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TooEarlyInterRATHOReportReportFromEUTRANValueCodec) encodeBudgetValue(value TooEarlyInterRATHOReportReportFromEUTRAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TooEarlyInterRATHOReportReportFromEUTRANValueCodec) encodeChanged(value TooEarlyInterRATHOReportReportFromEUTRAN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationReportAPERValue is the concrete APERValue[SONInformationReport].
type SONInformationReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformationReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReportAPERValue) WithoutReplay() SONInformationReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TransportInformationAPERValue is the concrete APERValue[TransportInformation].
type TransportInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TransportInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TransportInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TransportInformationAPERValue) WithoutReplay() TransportInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FailureEventReportAPERValue is the concrete APERValue[FailureEventReport].
type FailureEventReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   FailureEventReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FailureEventReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FailureEventReportAPERValue) WithoutReplay() FailureEventReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionAPERValue is the concrete APERValue[SONInformationExtension].
type SONInformationExtensionAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformationExtension

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionAPERValue) WithoutReplay() SONInformationExtensionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferCauseAPERValue is the concrete APERValue[SONtransferCause].
type SONtransferCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferCauseAPERValue) WithoutReplay() SONtransferCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionAPERValue is the concrete APERValue[SourceNodeIDExtension].
type SourceNodeIDExtensionAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceNodeIDExtension

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionAPERValue) WithoutReplay() SourceNodeIDExtensionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TooEarlyInterRATHOReportReportFromEUTRANAPERValue is the concrete APERValue[TooEarlyInterRATHOReportReportFromEUTRAN].
type TooEarlyInterRATHOReportReportFromEUTRANAPERValue struct {
	context s00.BridgeCodecContext
	Value   TooEarlyInterRATHOReportReportFromEUTRAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TooEarlyInterRATHOReportReportFromEUTRANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TooEarlyInterRATHOReportReportFromEUTRANAPERValue) WithoutReplay() TooEarlyInterRATHOReportReportFromEUTRANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifyItemBearerModReqExtIEsIEField uses the ProtocolIE-Field shape for object set E-RABToBeModifyItemBearerModReqExtIEs of TS 36.413.
type ERABToBeModifyItemBearerModReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeModifyItemBearerModReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsIEField) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifyItemBearerModReqExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABToBeModifyItemBearerModReqExtIEsValue

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

// ERABToBeModifyItemBearerModReqExtIEsIEContainer uses the ProtocolIE-Container shape for object set E-RABToBeModifyItemBearerModReqExtIEs of TS 36.413: a list of ERABToBeModifyItemBearerModReqExtIEsIEField values.
type ERABToBeModifyItemBearerModReqExtIEsIEContainer []ERABToBeModifyItemBearerModReqExtIEsIEField

// RerouteNASRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueERABIEContainerList].
type RerouteNASRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, error)
	encode  func(RerouteNASRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueERABIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) New(value RerouteNASRequestIEValueERABIEContainerList) (RerouteNASRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{RerouteNASRequest-IEs}} of TS 36.413: a list of information element fields.
type RerouteNASRequestIEValueERABIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueERABIEContainerList].
type S1RemovalRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, error)
	encode  func(S1RemovalRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueERABIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) New(value S1RemovalRequestIEValueERABIEContainerList) (S1RemovalRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{S1RemovalRequestIEs}} of TS 36.413: a list of information element fields.
type S1RemovalRequestIEValueERABIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueERABIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueERABIEContainerList].
type SONInformationExtensionIEIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueERABIEContainerList) (SONInformationExtensionIEIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueERABIEContainerList is E-RAB-IE-ContainerList {{SONInformation-ExtensionIE}} of TS 36.413: a list of information element fields.
type SONInformationExtensionIEIEValueERABIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEContainer is ProtocolIE-Container {{SONInformation-ExtensionIE}} of TS 36.413: a list of SONInformationExtensionIEIEField values.
type SONInformationExtensionIEIEContainer []SONInformationExtensionIEIEField

// TraceFailureIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[TraceFailureIndicationIEValueERABIEContainerList].
type TraceFailureIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueERABIEContainerList, error)
	encode  func(TraceFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEValueERABIEContainerListValueCodec) New(value TraceFailureIndicationIEValueERABIEContainerList) (TraceFailureIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value TraceFailureIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value TraceFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value TraceFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceFailureIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{TraceFailureIndicationIEs}} of TS 36.413: a list of information element fields.
type TraceFailureIndicationIEValueERABIEContainerList []TraceFailureIndicationIEValueProtocolIESingleContainer

// UEContextModificationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationIndicationIEValueERABIEContainerList].
type UEContextModificationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueERABIEContainerList) (UEContextModificationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextModificationIndicationIEs}} of TS 36.413: a list of information element fields.
type UEContextModificationIndicationIEValueERABIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnellingIEValueERABIEContainerList].
type UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList) (UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} of TS 36.413: a list of information element fields.
type UplinkS1cdma2000tunnellingIEValueERABIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

// ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ERABToBeModifyItemBearerModReqExtIEsExtField].
type ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, error)
	encode  func(ERABToBeModifyItemBearerModReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) New(value ERABToBeModifyItemBearerModReqExtIEsExtField) (ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ERABToBeModifyItemBearerModReqExtIEsExtContainer].
type ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, error)
	encode  func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) New(value ERABToBeModifyItemBearerModReqExtIEsExtContainer) (ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEFieldValueCodec is the concrete ValueCodec[RerouteNASRequestIEField].
type RerouteNASRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s23.RerouteNASRequestIEField, error)
	encode  func(s23.RerouteNASRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s23.RerouteNASRequestIEField, aper.DecodeState) (s23.RerouteNASRequestIEField, aper.Snapshot)
	compare func(s23.RerouteNASRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEFieldValueCodec) New(value s23.RerouteNASRequestIEField) (RerouteNASRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEFieldValueCodec) EncodeAPER(value RerouteNASRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEFieldValueCodec) encodeBudgetValue(value s23.RerouteNASRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEFieldValueCodec) encodeChanged(value s23.RerouteNASRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEFieldValueCodec is the concrete ValueCodec[S1RemovalRequestIEField].
type S1RemovalRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEField, error)
	encode  func(S1RemovalRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEField, aper.DecodeState) (S1RemovalRequestIEField, aper.Snapshot)
	compare func(S1RemovalRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEFieldValueCodec) New(value S1RemovalRequestIEField) (S1RemovalRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEFieldValueCodec) EncodeAPER(value S1RemovalRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEFieldValueCodec) encodeBudgetValue(value S1RemovalRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEFieldValueCodec) encodeChanged(value S1RemovalRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEFieldValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEField].
type SONInformationExtensionIEIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEField, error)
	encode  func(SONInformationExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEField, aper.DecodeState) (SONInformationExtensionIEIEField, aper.Snapshot)
	compare func(SONInformationExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEFieldValueCodec) New(value SONInformationExtensionIEIEField) (SONInformationExtensionIEIEFieldAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEFieldValueCodec) EncodeAPER(value SONInformationExtensionIEIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEFieldValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEFieldValueCodec) encodeChanged(value SONInformationExtensionIEIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceFailureIndicationIEFieldValueCodec is the concrete ValueCodec[TraceFailureIndicationIEField].
type TraceFailureIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndicationIEField, error)
	encode  func(TraceFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndicationIEField, aper.DecodeState) (TraceFailureIndicationIEField, aper.Snapshot)
	compare func(TraceFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEFieldValueCodec) New(value TraceFailureIndicationIEField) (TraceFailureIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEFieldValueCodec) EncodeAPER(value TraceFailureIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEFieldValueCodec) encodeBudgetValue(value TraceFailureIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEFieldValueCodec) encodeChanged(value TraceFailureIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEFieldValueCodec is the concrete ValueCodec[UEContextModificationIndicationIEField].
type UEContextModificationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEField, error)
	encode  func(UEContextModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEField, aper.DecodeState) (UEContextModificationIndicationIEField, aper.Snapshot)
	compare func(UEContextModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEFieldValueCodec) New(value UEContextModificationIndicationIEField) (UEContextModificationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEFieldValueCodec) EncodeAPER(value UEContextModificationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEFieldValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEFieldValueCodec) encodeChanged(value UEContextModificationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEFieldValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnellingIEField].
type UplinkS1cdma2000tunnellingIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, error)
	encode  func(UplinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEField, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) New(value UplinkS1cdma2000tunnellingIEField) (UplinkS1cdma2000tunnellingIEFieldAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEContainerValueCodec is the concrete ValueCodec[RerouteNASRequestIEContainer].
type RerouteNASRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s23.RerouteNASRequestIEContainer, error)
	encode  func(s23.RerouteNASRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s23.RerouteNASRequestIEContainer, aper.DecodeState) (s23.RerouteNASRequestIEContainer, aper.Snapshot)
	compare func(s23.RerouteNASRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEContainerValueCodec) New(value s23.RerouteNASRequestIEContainer) (s23.RerouteNASRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return s23.RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s23.RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s23.RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s23.RerouteNASRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s23.RerouteNASRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s23.RerouteNASRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s23.RerouteNASRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s23.RerouteNASRequestIEContainerAPERValue {
			sealed := s23.RerouteNASRequestIEContainerAPERValue{Value: value}
			*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReplay(&sealed) = replay
			*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s23.RerouteNASRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEContainerValueCodec) EncodeAPER(value s23.RerouteNASRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s23.BridgeRerouteNASRequestIEContainerAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s23.BridgeRerouteNASRequestIEContainerAPERValueFieldContext(&value) == c.context && !fresh && (*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s23.BridgeRerouteNASRequestIEContainerAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEContainerValueCodec) encodeBudgetValue(value s23.RerouteNASRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEContainerValueCodec) encodeChanged(value s23.RerouteNASRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEContainerValueCodec is the concrete ValueCodec[S1RemovalRequestIEContainer].
type S1RemovalRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEContainer, error)
	encode  func(S1RemovalRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEContainer, aper.DecodeState) (S1RemovalRequestIEContainer, aper.Snapshot)
	compare func(S1RemovalRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEContainerValueCodec) New(value S1RemovalRequestIEContainer) (S1RemovalRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEContainerValueCodec) EncodeAPER(value S1RemovalRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEContainerValueCodec) encodeBudgetValue(value S1RemovalRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEContainerValueCodec) encodeChanged(value S1RemovalRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEContainerValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEContainer].
type SONInformationExtensionIEIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEContainer, error)
	encode  func(SONInformationExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEContainer, aper.DecodeState) (SONInformationExtensionIEIEContainer, aper.Snapshot)
	compare func(SONInformationExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEContainerValueCodec) New(value SONInformationExtensionIEIEContainer) (SONInformationExtensionIEIEContainerAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEContainerValueCodec) EncodeAPER(value SONInformationExtensionIEIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEContainerValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEContainerValueCodec) encodeChanged(value SONInformationExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceFailureIndicationIEContainerValueCodec is the concrete ValueCodec[TraceFailureIndicationIEContainer].
type TraceFailureIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndicationIEContainer, error)
	encode  func(TraceFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndicationIEContainer, aper.DecodeState) (TraceFailureIndicationIEContainer, aper.Snapshot)
	compare func(TraceFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEContainerValueCodec) New(value TraceFailureIndicationIEContainer) (TraceFailureIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEContainerValueCodec) EncodeAPER(value TraceFailureIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEContainerValueCodec) encodeBudgetValue(value TraceFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEContainerValueCodec) encodeChanged(value TraceFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEContainerValueCodec is the concrete ValueCodec[UEContextModificationIndicationIEContainer].
type UEContextModificationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEContainer, error)
	encode  func(UEContextModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEContainer, aper.DecodeState) (UEContextModificationIndicationIEContainer, aper.Snapshot)
	compare func(UEContextModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEContainerValueCodec) New(value UEContextModificationIndicationIEContainer) (UEContextModificationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEContainerValueCodec) EncodeAPER(value UEContextModificationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEContainerValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEContainerValueCodec) encodeChanged(value UEContextModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEContainerValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnellingIEContainer].
type UplinkS1cdma2000tunnellingIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, error)
	encode  func(UplinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) New(value UplinkS1cdma2000tunnellingIEContainer) (UplinkS1cdma2000tunnellingIEContainerAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueProtocolErrorIEContainerList].
type RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(RerouteNASRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) New(value RerouteNASRequestIEValueProtocolErrorIEContainerList) (RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{RerouteNASRequest-IEs}} of TS 36.413: a list of information element fields.
type RerouteNASRequestIEValueProtocolErrorIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueProtocolErrorIEContainerList].
type S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(S1RemovalRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) New(value S1RemovalRequestIEValueProtocolErrorIEContainerList) (S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{S1RemovalRequestIEs}} of TS 36.413: a list of information element fields.
type S1RemovalRequestIEValueProtocolErrorIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueProtocolErrorIEContainerList].
type SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList) (SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{SONInformation-ExtensionIE}} of TS 36.413: a list of information element fields.
type SONInformationExtensionIEIEValueProtocolErrorIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[TraceFailureIndicationIEValueProtocolErrorIEContainerList].
type TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value TraceFailureIndicationIEValueProtocolErrorIEContainerList) (TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value TraceFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value TraceFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceFailureIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{TraceFailureIndicationIEs}} of TS 36.413: a list of information element fields.
type TraceFailureIndicationIEValueProtocolErrorIEContainerList []TraceFailureIndicationIEValueProtocolIESingleContainer

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationIndicationIEValueProtocolErrorIEContainerList].
type UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList) (UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextModificationIndicationIEs}} of TS 36.413: a list of information element fields.
type UEContextModificationIndicationIEValueProtocolErrorIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList].
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} of TS 36.413: a list of information element fields.
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

// RerouteNASRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueProtocolIEContainerList].
type RerouteNASRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, error)
	encode  func(RerouteNASRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueProtocolIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) New(value RerouteNASRequestIEValueProtocolIEContainerList) (RerouteNASRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {RerouteNASRequest-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type RerouteNASRequestIEValueProtocolIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueProtocolIEContainerList].
type S1RemovalRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, error)
	encode  func(S1RemovalRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) New(value S1RemovalRequestIEValueProtocolIEContainerList) (S1RemovalRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {S1RemovalRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type S1RemovalRequestIEValueProtocolIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueProtocolIEContainerList].
type SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueProtocolIEContainerList) (SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {SONInformation-ExtensionIE} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type SONInformationExtensionIEIEValueProtocolIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// TraceFailureIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[TraceFailureIndicationIEValueProtocolIEContainerList].
type TraceFailureIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueProtocolIEContainerList, error)
	encode  func(TraceFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) New(value TraceFailureIndicationIEValueProtocolIEContainerList) (TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceFailureIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {TraceFailureIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type TraceFailureIndicationIEValueProtocolIEContainerList []TraceFailureIndicationIEValueProtocolIESingleContainer

// UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationIndicationIEValueProtocolIEContainerList].
type UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueProtocolIEContainerList) (UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextModificationIndicationIEValueProtocolIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList].
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UplinkS1cdma2000tunnellingIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

// RerouteNASRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueERABIEContainerList].
type RerouteNASRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueERABIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{RerouteNASRequest-IEs}} of TS 36.413: a single information element field.
type RerouteNASRequestIEValueProtocolIESingleContainer = s23.RerouteNASRequestIEField

// S1RemovalRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueERABIEContainerList].
type S1RemovalRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueERABIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{S1RemovalRequestIEs}} of TS 36.413: a single information element field.
type S1RemovalRequestIEValueProtocolIESingleContainer = S1RemovalRequestIEField

// SONInformationExtensionIEIEValueERABIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueERABIEContainerList].
type SONInformationExtensionIEIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueERABIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{SONInformation-ExtensionIE}} of TS 36.413: a single information element field.
type SONInformationExtensionIEIEValueProtocolIESingleContainer = SONInformationExtensionIEIEField

// TraceFailureIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[TraceFailureIndicationIEValueERABIEContainerList].
type TraceFailureIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceFailureIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() TraceFailureIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceFailureIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{TraceFailureIndicationIEs}} of TS 36.413: a single information element field.
type TraceFailureIndicationIEValueProtocolIESingleContainer = TraceFailureIndicationIEField

// UEContextModificationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextModificationIndicationIEValueERABIEContainerList].
type UEContextModificationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextModificationIndicationIEs}} of TS 36.413: a single information element field.
type UEContextModificationIndicationIEValueProtocolIESingleContainer = UEContextModificationIndicationIEField

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue is the concrete APERValue[UplinkS1cdma2000tunnellingIEValueERABIEContainerList].
type UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UplinkS1cdma2000tunnellingIEs}} of TS 36.413: a single information element field.
type UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer = UplinkS1cdma2000tunnellingIEField

// ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue is the concrete APERValue[ERABToBeModifyItemBearerModReqExtIEsExtField].
type ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifyItemBearerModReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue is the concrete APERValue[ERABToBeModifyItemBearerModReqExtIEsExtContainer].
type ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifyItemBearerModReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEFieldAPERValue is the concrete APERValue[RerouteNASRequestIEField].
type RerouteNASRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         s23.RerouteNASRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEFieldAPERValue) WithoutReplay() RerouteNASRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEFieldAPERValue is the concrete APERValue[S1RemovalRequestIEField].
type S1RemovalRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEFieldAPERValue) WithoutReplay() S1RemovalRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEFieldAPERValue is the concrete APERValue[SONInformationExtensionIEIEField].
type SONInformationExtensionIEIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEFieldAPERValue) WithoutReplay() SONInformationExtensionIEIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceFailureIndicationIEFieldAPERValue is the concrete APERValue[TraceFailureIndicationIEField].
type TraceFailureIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceFailureIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEFieldAPERValue) WithoutReplay() TraceFailureIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEFieldAPERValue is the concrete APERValue[UEContextModificationIndicationIEField].
type UEContextModificationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEFieldAPERValue) WithoutReplay() UEContextModificationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEFieldAPERValue is the concrete APERValue[UplinkS1cdma2000tunnellingIEField].
type UplinkS1cdma2000tunnellingIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEFieldAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEContainerAPERValue is the concrete APERValue[S1RemovalRequestIEContainer].
type S1RemovalRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEContainerAPERValue) WithoutReplay() S1RemovalRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEContainerAPERValue is the concrete APERValue[SONInformationExtensionIEIEContainer].
type SONInformationExtensionIEIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEContainerAPERValue) WithoutReplay() SONInformationExtensionIEIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceFailureIndicationIEContainerAPERValue is the concrete APERValue[TraceFailureIndicationIEContainer].
type TraceFailureIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceFailureIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEContainerAPERValue) WithoutReplay() TraceFailureIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEContainerAPERValue is the concrete APERValue[UEContextModificationIndicationIEContainer].
type UEContextModificationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEContainerAPERValue) WithoutReplay() UEContextModificationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEContainerAPERValue is the concrete APERValue[UplinkS1cdma2000tunnellingIEContainer].
type UplinkS1cdma2000tunnellingIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEContainerAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueProtocolErrorIEContainerList].
type RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueProtocolErrorIEContainerList].
type S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueProtocolErrorIEContainerList].
type SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[TraceFailureIndicationIEValueProtocolErrorIEContainerList].
type TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceFailureIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() TraceFailureIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextModificationIndicationIEValueProtocolErrorIEContainerList].
type UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList].
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueProtocolIEContainerList].
type RerouteNASRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueProtocolIEContainerList].
type S1RemovalRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueProtocolIEContainerList].
type SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceFailureIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[TraceFailureIndicationIEValueProtocolIEContainerList].
type TraceFailureIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceFailureIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() TraceFailureIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextModificationIndicationIEValueProtocolIEContainerList].
type UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList].
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABToBeModifyItemBearerModReqExtIEsValue(v *ERABToBeModifyItemBearerModReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(185):
			{
				f := s.Begin()
				s.Bool(v.rowTransportInformation == nil)
				if v.rowTransportInformation != nil {
					BridgeCaptureS1APTransportInformation(v.rowTransportInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeModifyItemBearerModReqExtIEsValue {
	BridgeCaptureS1APERABToBeModifyItemBearerModReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeModifyItemBearerModReqExtIEsValue(v *ERABToBeModifyItemBearerModReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(185):
			{
				f := s.Begin()
				s.Bool(v.rowTransportInformation == nil)
				if v.rowTransportInformation != nil {
					BridgeCompareS1APTransportInformation(v.rowTransportInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeModifyItemBearerModReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APFailureEventReport(v *FailureEventReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, nil, false)
	}
	switch v.Choice {
	case s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		{
			f := s.Begin()
			s.Bool(v.TooEarlyInterRATHOReportFromEUTRAN == nil)
			if v.TooEarlyInterRATHOReportFromEUTRAN != nil {
				BridgeCaptureS1APTooEarlyInterRATHOReportReportFromEUTRAN(v.TooEarlyInterRATHOReportFromEUTRAN, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APFailureEventReport(v *FailureEventReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		{
			f := s.Begin()
			s.Bool(v.TooEarlyInterRATHOReportFromEUTRAN == nil)
			if v.TooEarlyInterRATHOReportFromEUTRAN != nil {
				BridgeCompareS1APTooEarlyInterRATHOReportReportFromEUTRAN(v.TooEarlyInterRATHOReportFromEUTRAN, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APS1RemovalRequestIEValue(v *S1RemovalRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s21.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalRequestIEValue) captureSemantics(s aper.SemanticCapture) S1RemovalRequestIEValue {
	BridgeCaptureS1APS1RemovalRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1RemovalRequestIEValue(v *S1RemovalRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s21.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1RemovalRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONInformationExtension(v *SONInformationExtension, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSONInformationExtension(v *SONInformationExtension, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSONInformationExtensionIEIEValue(v *SONInformationExtensionIEIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(206):
			{
				f := s.Begin()
				s.Bool(v.rowSONInformationReport == nil)
				if v.rowSONInformationReport != nil {
					BridgeCaptureS1APSONInformationReport(v.rowSONInformationReport, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationExtensionIEIEValue) captureSemantics(s aper.SemanticCapture) SONInformationExtensionIEIEValue {
	BridgeCaptureS1APSONInformationExtensionIEIEValue(&v, &s)
	return v
}
func BridgeCompareS1APSONInformationExtensionIEIEValue(v *SONInformationExtensionIEIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(206):
			{
				f := s.Begin()
				s.Bool(v.rowSONInformationReport == nil)
				if v.rowSONInformationReport != nil {
					BridgeCompareS1APSONInformationReport(v.rowSONInformationReport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationExtensionIEIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSONInformationExtensionIEIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONInformationReport(v *SONInformationReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, nil, false)
	}
	switch v.Choice {
	case s00.SONInformationReportChoiceRLFReportInformation:
		{
			f := s.Begin()
			s.Bool(v.RLFReportInformation == nil)
			if v.RLFReportInformation != nil {
				s23.BridgeCaptureS1APRLFReportInformation(v.RLFReportInformation, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSONInformationReport(v *SONInformationReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.SONInformationReportChoiceRLFReportInformation:
		{
			f := s.Begin()
			s.Bool(v.RLFReportInformation == nil)
			if v.RLFReportInformation != nil {
				s23.BridgeCompareS1APRLFReportInformation(v.RLFReportInformation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSONtransferCause(v *SONtransferCause, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, nil, false)
	}
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.CellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.MultiCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s00.BridgeCaptureS1APHOReportingCause(v.HOReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s00.BridgeCaptureS1APCellActivationCause(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				s00.BridgeCaptureS1APCellStateIndicationCause(v.EnergySavingsIndication, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s00.BridgeCaptureS1APFailureEventReportingCause(v.FailureEventReporting, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferCause(v *SONtransferCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.CellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.MultiCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s02.BridgeCompareS1APHOReportingCause(v.HOReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s02.BridgeCompareS1APCellActivationCause(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				s02.BridgeCompareS1APCellStateIndicationCause(v.EnergySavingsIndication, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s02.BridgeCompareS1APFailureEventReportingCause(v.FailureEventReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APSourceNodeIDExtension(v *SourceNodeIDExtension, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSourceNodeIDExtension(v *SourceNodeIDExtension, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTooEarlyInterRATHOReportReportFromEUTRAN(v *TooEarlyInterRATHOReportReportFromEUTRAN, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.UERLFReportContainer)
	{
		f := s.Begin()
		s.Bool(v.MobilityInformation == nil)
		if v.MobilityInformation != nil {
			s00.BridgeCaptureS1APSonTransferIEsMobilityInformation(v.MobilityInformation, s)
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTooEarlyInterRATHOReportReportFromEUTRAN(v *TooEarlyInterRATHOReportReportFromEUTRAN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.UERLFReportContainer)
	{
		f := s.Begin()
		s.Bool(v.MobilityInformation == nil)
		if v.MobilityInformation != nil {
			s08.BridgeCompareS1APSonTransferIEsMobilityInformation(v.MobilityInformation, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTraceFailureIndicationIEValue(v *TraceFailureIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceFailureIndicationIEValue) captureSemantics(s aper.SemanticCapture) TraceFailureIndicationIEValue {
	BridgeCaptureS1APTraceFailureIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APTraceFailureIndicationIEValue(v *TraceFailureIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceFailureIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APTraceFailureIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTransportInformation(v *TransportInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.ULGTPTEID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTransportInformation(v *TransportInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.ULGTPTEID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationIndicationIEValue(v *UEContextModificationIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s17.BridgeCaptureS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationIndicationIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationIndicationIEValue {
	BridgeCaptureS1APUEContextModificationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationIndicationIEValue(v *UEContextModificationIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s17.BridgeCompareS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUplinkS1cdma2000tunnellingIEValue(v *UplinkS1cdma2000tunnellingIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(71):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000RATType == nil)
				if v.rowCdma2000RATType != nil {
					s00.BridgeCaptureS1APCdma2000RATType(v.rowCdma2000RATType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(72):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000SectorID == nil)
				if v.rowCdma2000SectorID != nil {
					s00.BridgeCaptureS1APCdma2000SectorID(v.rowCdma2000SectorID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(84):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HORequiredIndication == nil)
				if v.rowCdma2000HORequiredIndication != nil {
					s00.BridgeCaptureS1APCdma2000HORequiredIndication(v.rowCdma2000HORequiredIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(102):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXSRVCCInfo == nil)
				if v.rowCdma2000OneXSRVCCInfo != nil {
					s17.BridgeCaptureS1APCdma2000OneXSRVCCInfo(v.rowCdma2000OneXSRVCCInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(97):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXRAND == nil)
				if v.rowCdma2000OneXRAND != nil {
					s00.BridgeCaptureS1APCdma2000OneXRAND(v.rowCdma2000OneXRAND, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s00.BridgeCaptureS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(140):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANRoundTripDelayEstimationInfo == nil)
				if v.rowEUTRANRoundTripDelayEstimationInfo != nil {
					s00.BridgeCaptureS1APEUTRANRoundTripDelayEstimationInfo(v.rowEUTRANRoundTripDelayEstimationInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkS1cdma2000tunnellingIEValue) captureSemantics(s aper.SemanticCapture) UplinkS1cdma2000tunnellingIEValue {
	BridgeCaptureS1APUplinkS1cdma2000tunnellingIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUplinkS1cdma2000tunnellingIEValue(v *UplinkS1cdma2000tunnellingIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(71):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000RATType == nil)
				if v.rowCdma2000RATType != nil {
					s02.BridgeCompareS1APCdma2000RATType(v.rowCdma2000RATType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(72):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000SectorID == nil)
				if v.rowCdma2000SectorID != nil {
					s02.BridgeCompareS1APCdma2000SectorID(v.rowCdma2000SectorID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(84):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HORequiredIndication == nil)
				if v.rowCdma2000HORequiredIndication != nil {
					s02.BridgeCompareS1APCdma2000HORequiredIndication(v.rowCdma2000HORequiredIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(102):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXSRVCCInfo == nil)
				if v.rowCdma2000OneXSRVCCInfo != nil {
					s17.BridgeCompareS1APCdma2000OneXSRVCCInfo(v.rowCdma2000OneXSRVCCInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(97):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXRAND == nil)
				if v.rowCdma2000OneXRAND != nil {
					s02.BridgeCompareS1APCdma2000OneXRAND(v.rowCdma2000OneXRAND, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s02.BridgeCompareS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(140):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANRoundTripDelayEstimationInfo == nil)
				if v.rowEUTRANRoundTripDelayEstimationInfo != nil {
					s02.BridgeCompareS1APEUTRANRoundTripDelayEstimationInfo(v.rowEUTRANRoundTripDelayEstimationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkS1cdma2000tunnellingIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUplinkS1cdma2000tunnellingIEValue(&v, &s)
	return s
}

// SONInformationExtension represents the ASN.1 type SONInformation-Extension (SEQUENCE).
type SONInformationExtension struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Id               s00.ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            runtime.RawValue     `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// SONInformationReport represents the ASN.1 CHOICE type SONInformationReport.
type SONInformationReport struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	Choice               int
	perPadding           aper.CompletePadding      `json:"-"`
	perOpenTypePadding   aper.CompletePadding      `json:"-"`
	UnknownExtension     *aper.ChoiceExtension     `json:"UnknownExtension,omitempty"`
	RLFReportInformation *s23.RLFReportInformation `json:"RLFReportInformation,omitempty"`
}

// SourceNodeIDExtension represents the ASN.1 type SourceNodeID-Extension (SEQUENCE).
type SourceNodeIDExtension struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Id               s00.ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            runtime.RawValue     `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// TransportInformation represents the ASN.1 type TransportInformation (SEQUENCE).
type TransportInformation struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	TransportLayerAddress s00.TransportLayerAddress `asn1:"tag:0,context,implicit"`
	ULGTPTEID             s00.GTPTEID               `asn1:"tag:1,context,implicit"`
	extCount              int64                     `asn1:"-" json:"-"`
	extPresent            []bool                    `asn1:"-" json:"-"`
	extData               [][]byte                  `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// MarshalAPER encodes SONInformationExtension to APER format.
func (v *SONInformationExtension) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONInformationExtension) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SONInformationExtension from APER format.
func (v *SONInformationExtension) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SONInformationExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	bb.EnterComponent("SONInformationExtension")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformationExtension")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONInformationExtension) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationExtension{}
	val_id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(val_id)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	toleranceMark_value := bb.EnterComponent("Value")
	openData_value, err := aper.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SONInformationReport to APER format.
func (v *SONInformationReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONInformationReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONInformationReport:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONInformationReport:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "SONInformationReport:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "SONInformationReport:", v.Choice)
	}
	switch v.Choice {
	case s00.SONInformationReportChoiceRLFReportInformation:
		if v.RLFReportInformation == nil {
			return fmt.Errorf("choice alternative rLFReportInformation is nil")
		}
		if err := s23.BridgeRLFReportInformationMethodMarshalAPERTo(v.RLFReportInformation, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding rLFReportInformation: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONInformationReport choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONInformationReport from APER format.
func (v *SONInformationReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SONInformationReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	bb.EnterComponent("SONInformationReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformationReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONInformationReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReport{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.SONInformationReportChoiceRLFReportInformation:
		toleranceMark_rlfreportinformation := bb.EnterComponent("RLFReportInformation")
		var dec_rlfreportinformation s23.RLFReportInformation
		if err := s23.BridgeRLFReportInformationMethodUnmarshalAPERFrom(&dec_rlfreportinformation, bb); err != nil {
			return runtime.WrapDecodePath(err, "RLFReportInformation")
		}
		if err := aper.ChargeValue(bb, dec_rlfreportinformation); err != nil {
			return err
		}
		v.RLFReportInformation = &dec_rlfreportinformation
		bb.LeaveComponent(toleranceMark_rlfreportinformation)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SourceNodeIDExtension to APER format.
func (v *SourceNodeIDExtension) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SourceNodeIDExtension) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SourceNodeIDExtension from APER format.
func (v *SourceNodeIDExtension) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SourceNodeIDExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	bb.EnterComponent("SourceNodeIDExtension")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtension")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SourceNodeIDExtension) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNodeIDExtension{}
	val_id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(val_id)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	toleranceMark_value := bb.EnterComponent("Value")
	openData_value, err := aper.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TransportInformation to APER format.
func (v *TransportInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TransportInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.ULGTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes TransportInformation from APER format.
func (v *TransportInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TransportInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	bb.EnterComponent("TransportInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TransportInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *TransportInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TransportInformation{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_ulgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULGTPTEID")
	}
	v.ULGTPTEID = s00.GTPTEID(val_ulgtpteid)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformationExtension) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationExtension", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformationExtension", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformationExtension) WithoutReplay() SONInformationExtension {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformationExtension
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformationReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformationReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformationReport) WithoutReplay() SONInformationReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformationReport
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SourceNodeIDExtension) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNodeIDExtension", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceNodeIDExtension", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceNodeIDExtension) WithoutReplay() SourceNodeIDExtension {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceNodeIDExtension
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TransportInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TransportInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TransportInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TransportInformation) WithoutReplay() TransportInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TransportInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *TransportInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TransportInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TransportInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SONInformationExtension) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformationExtension")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformationExtension) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformationExtension")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformationExtension(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformationExtension")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformationExtension")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformationExtension) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformationExtension")
}
func (v *SONInformationExtension) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformationExtension")
}
func (v *SONInformationExtension) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformationExtension(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SONInformationExtension) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformationExtension) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SONInformationReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformationReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformationReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformationReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformationReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformationReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformationReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformationReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformationReport")
}
func (v *SONInformationReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformationReport")
}
func (v *SONInformationReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformationReport(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SONInformationReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformationReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SourceNodeIDExtension) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceNodeIDExtension")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceNodeIDExtension) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceNodeIDExtension")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceNodeIDExtension(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceNodeIDExtension")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceNodeIDExtension")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceNodeIDExtension) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceNodeIDExtension")
}
func (v *SourceNodeIDExtension) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceNodeIDExtension")
}
func (v *SourceNodeIDExtension) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceNodeIDExtension(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SourceNodeIDExtension) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceNodeIDExtension) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TransportInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TransportInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TransportInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TransportInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTransportInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TransportInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TransportInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TransportInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TransportInformation")
}
func (v *TransportInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TransportInformation")
}
func (v *TransportInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTransportInformation(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *TransportInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TransportInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformationExtension) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformationExtension")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformationExtension
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformationExtension(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformationExtension{}
		return report, aper.OperationError(err, "SONInformationExtension")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformationExtension")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformationReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformationReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformationReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformationReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformationReport{}
		return report, aper.OperationError(err, "SONInformationReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformationReport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SourceNodeIDExtension) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceNodeIDExtension")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceNodeIDExtension
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceNodeIDExtension(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceNodeIDExtension{}
		return report, aper.OperationError(err, "SourceNodeIDExtension")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceNodeIDExtension")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TransportInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TransportInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TransportInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTransportInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TransportInformation{}
		return report, aper.OperationError(err, "TransportInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TransportInformation")
}

// NewSONInformationReportUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONInformationReportUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONInformationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	value := SONInformationReport{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONInformationReportUnknownExtension")
}

// SONtransferCause represents the ASN.1 CHOICE type SONtransferCause.
type SONtransferCause struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding            `json:"-"`
	perOpenTypePadding              aper.CompletePadding            `json:"-"`
	UnknownExtension                *aper.ChoiceExtension           `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *s00.CellLoadReportingCause     `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *s00.CellLoadReportingCause     `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *s00.CellLoadReportingCause     `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *s00.HOReportingCause           `json:"HOReporting,omitempty"`
	EutranCellActivation            *s00.CellActivationCause        `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *s00.CellStateIndicationCause   `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *s00.FailureEventReportingCause `json:"FailureEventReporting,omitempty"`
}

// FailureEventReport represents the ASN.1 CHOICE type FailureEventReport.
type FailureEventReport struct {
	replay                             aper.Snapshot
	stream                             aper.WireSpan
	received                           bool
	withoutReplay                      bool
	receivedAbsolute                   bool
	receivedBytes                      aper.WireSpan
	receivedLocation                   aper.Location
	Choice                             int
	perPadding                         aper.CompletePadding                      `json:"-"`
	perOpenTypePadding                 aper.CompletePadding                      `json:"-"`
	UnknownExtension                   *aper.ChoiceExtension                     `json:"UnknownExtension,omitempty"`
	TooEarlyInterRATHOReportFromEUTRAN *TooEarlyInterRATHOReportReportFromEUTRAN `json:"TooEarlyInterRATHOReportFromEUTRAN,omitempty"`
}

// TooEarlyInterRATHOReportReportFromEUTRAN represents the ASN.1 type TooEarlyInterRATHOReportReportFromEUTRAN (SEQUENCE).
type TooEarlyInterRATHOReportReportFromEUTRAN struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	UERLFReportContainer []byte                                 `asn1:"tag:0,context,implicit"`
	MobilityInformation  *s00.SonTransferIEsMobilityInformation `asn1:"tag:1,context,implicit,optional" json:"MobilityInformation,omitempty"`
	extCount             int64                                  `asn1:"-" json:"-"`
	extPresent           []bool                                 `asn1:"-" json:"-"`
	extData              [][]byte                               `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// MarshalAPER encodes SONtransferCause to APER format.
func (v *SONtransferCause) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferCause) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferCause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferCause:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferCause:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "SONtransferCause:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.SONtransferCauseChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.MultiCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EventTriggeredCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.HOReporting), 3, true); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EutranCellActivation), 3, true); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferCauseChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EnergySavingsIndication), 3, true); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case s00.SONtransferCauseChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.FailureEventReporting), 3, true); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferCause extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s08.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CellLoadReporting), 3, true); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferCause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferCause from APER format.
func (v *SONtransferCause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SONtransferCause) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	bb.EnterComponent("SONtransferCause")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferCause")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferCause) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferCause{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 6 {
			if err := openExtension.ObserveUnknown(bb); err != nil {
				return err
			}
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.SONtransferCauseChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			val_multicellloadreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MultiCellLoadReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			tmp_multicellloadreporting := s00.CellLoadReportingCause(val_multicellloadreporting)
			if err := aper.ChargeValue(inner, tmp_multicellloadreporting); err != nil {
				return err
			}
			v.MultiCellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_multicellloadreporting)))

		case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			val_eventtriggeredcellloadreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EventTriggeredCellLoadReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			tmp_eventtriggeredcellloadreporting := s00.CellLoadReportingCause(val_eventtriggeredcellloadreporting)
			if err := aper.ChargeValue(inner, tmp_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_eventtriggeredcellloadreporting)))

		case s00.SONtransferCauseChoiceHOReporting:
			extensionPath = "HOReporting"
			val_horeporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "HOReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			tmp_horeporting := s00.HOReportingCause(val_horeporting)
			if err := aper.ChargeValue(inner, tmp_horeporting); err != nil {
				return err
			}
			v.HOReporting = (*s00.HOReportingCause)(bb.OwnInt64(int64(tmp_horeporting)))

		case s00.SONtransferCauseChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			val_eutrancellactivation, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EutranCellActivation"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			tmp_eutrancellactivation := s00.CellActivationCause(val_eutrancellactivation)
			if err := aper.ChargeValue(inner, tmp_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = (*s00.CellActivationCause)(bb.OwnInt64(int64(tmp_eutrancellactivation)))

		case s00.SONtransferCauseChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			val_energysavingsindication, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnergySavingsIndication"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			tmp_energysavingsindication := s00.CellStateIndicationCause(val_energysavingsindication)
			if err := aper.ChargeValue(inner, tmp_energysavingsindication); err != nil {
				return err
			}
			v.EnergySavingsIndication = (*s00.CellStateIndicationCause)(bb.OwnInt64(int64(tmp_energysavingsindication)))

		case s00.SONtransferCauseChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			val_failureeventreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "FailureEventReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			tmp_failureeventreporting := s00.FailureEventReportingCause(val_failureeventreporting)
			if err := aper.ChargeValue(inner, tmp_failureeventreporting); err != nil {
				return err
			}
			v.FailureEventReporting = (*s00.FailureEventReportingCause)(bb.OwnInt64(int64(tmp_failureeventreporting)))

		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		val_cellloadreporting, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellLoadReporting"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
		}
		tmp_cellloadreporting := s00.CellLoadReportingCause(val_cellloadreporting)
		if err := aper.ChargeValue(bb, tmp_cellloadreporting); err != nil {
			return err
		}
		v.CellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_cellloadreporting)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes FailureEventReport to APER format.
func (v *FailureEventReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *FailureEventReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "FailureEventReport:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "FailureEventReport:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "FailureEventReport:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "FailureEventReport:", v.Choice)
	}
	switch v.Choice {
	case s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		if v.TooEarlyInterRATHOReportFromEUTRAN == nil {
			return fmt.Errorf("choice alternative tooEarlyInterRATHOReportFromEUTRAN is nil")
		}
		if err := v.TooEarlyInterRATHOReportFromEUTRAN.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tooEarlyInterRATHOReportFromEUTRAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown FailureEventReport choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes FailureEventReport from APER format.
func (v *FailureEventReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *FailureEventReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	bb.EnterComponent("FailureEventReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "FailureEventReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *FailureEventReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = FailureEventReport{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		toleranceMark_tooearlyinterrathoreportfromeutran := bb.EnterComponent("TooEarlyInterRATHOReportFromEUTRAN")
		var dec_tooearlyinterrathoreportfromeutran TooEarlyInterRATHOReportReportFromEUTRAN
		if err := dec_tooearlyinterrathoreportfromeutran.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportFromEUTRAN")
		}
		if err := aper.ChargeValue(bb, dec_tooearlyinterrathoreportfromeutran); err != nil {
			return err
		}
		v.TooEarlyInterRATHOReportFromEUTRAN = &dec_tooearlyinterrathoreportfromeutran
		bb.LeaveComponent(toleranceMark_tooearlyinterrathoreportfromeutran)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TooEarlyInterRATHOReportReportFromEUTRAN to APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,
		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.MobilityInformation != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, v.UERLFReportContainer, 0, 0, false); err != nil {
		return fmt.Errorf("encoding uERLFReportContainer: %w", err)
	}
	if v.MobilityInformation != nil {
		if err := aper.EncodeBitStringAligned(bb, v.MobilityInformation.Bytes, v.MobilityInformation.BitLength, 32, 32, true); err != nil {
			return fmt.Errorf("encoding mobilityInformation: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes TooEarlyInterRATHOReportReportFromEUTRAN from APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	bb.EnterComponent("TooEarlyInterRATHOReportReportFromEUTRAN")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	padding, err := aper.CaptureFinalBits(bb, "TooEarlyInterRATHOReportReportFromEUTRAN")
	if err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	v.perPadding = padding
	return nil
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TooEarlyInterRATHOReportReportFromEUTRAN{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mobilityinformation, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uerlfreportcontainer, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UERLFReportContainer")
	}
	v.UERLFReportContainer = val_uerlfreportcontainer
	if opt_mobilityinformation {
		bsBytes_mobilityinformation, bsBitLen_mobilityinformation, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "MobilityInformation")
		}
		tmp_mobilityinformation := runtime.BitString{Bytes: bsBytes_mobilityinformation, BitLength: bsBitLen_mobilityinformation}
		if err := aper.ChargeValue(bb, tmp_mobilityinformation); err != nil {
			return err
		}
		v.MobilityInformation = &tmp_mobilityinformation
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "Annex B.2"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *FailureEventReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "FailureEventReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "FailureEventReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v FailureEventReport) WithoutReplay() FailureEventReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero FailureEventReport
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferCause) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferCause", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferCause", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferCause) WithoutReplay() SONtransferCause {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferCause
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TooEarlyInterRATHOReportReportFromEUTRAN", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TooEarlyInterRATHOReportReportFromEUTRAN", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TooEarlyInterRATHOReportReportFromEUTRAN) WithoutReplay() TooEarlyInterRATHOReportReportFromEUTRAN {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TooEarlyInterRATHOReportReportFromEUTRAN
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TooEarlyInterRATHOReportReportFromEUTRAN.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TooEarlyInterRATHOReportReportFromEUTRAN.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TooEarlyInterRATHOReportReportFromEUTRAN.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TooEarlyInterRATHOReportReportFromEUTRAN.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *FailureEventReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "FailureEventReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *FailureEventReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "FailureEventReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APFailureEventReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "FailureEventReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "FailureEventReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *FailureEventReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "FailureEventReport")
}
func (v *FailureEventReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "FailureEventReport")
}
func (v *FailureEventReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APFailureEventReport(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *FailureEventReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *FailureEventReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SONtransferCause) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferCause")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferCause) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferCause")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferCause(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferCause")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferCause")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferCause) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferCause")
}
func (v *SONtransferCause) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferCause")
}
func (v *SONtransferCause) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferCause(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SONtransferCause) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferCause) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTooEarlyInterRATHOReportReportFromEUTRAN(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TooEarlyInterRATHOReportReportFromEUTRAN")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTooEarlyInterRATHOReportReportFromEUTRAN(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *FailureEventReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "FailureEventReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded FailureEventReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APFailureEventReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = FailureEventReport{}
		return report, aper.OperationError(err, "FailureEventReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "FailureEventReport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferCause) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferCause")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferCause
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferCause(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferCause{}
		return report, aper.OperationError(err, "SONtransferCause")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferCause")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TooEarlyInterRATHOReportReportFromEUTRAN
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTooEarlyInterRATHOReportReportFromEUTRAN(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TooEarlyInterRATHOReportReportFromEUTRAN{}
		return report, aper.OperationError(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TooEarlyInterRATHOReportReportFromEUTRAN")
}

// NewFailureEventReportUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewFailureEventReportUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (FailureEventReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return FailureEventReport{}, aper.OperationError(err, "FailureEventReportUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return FailureEventReport{}, aper.OperationError(err, "FailureEventReportUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return FailureEventReport{}, aper.OperationError(err, "FailureEventReportUnknownExtension")
	}
	value := FailureEventReport{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return FailureEventReport{}, aper.OperationError(err, "FailureEventReportUnknownExtension")
	}
	return value, aper.OperationError(nil, "FailureEventReportUnknownExtension")
}

// NewSONtransferCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferCauseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	value := SONtransferCause{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferCauseUnknownExtension")
}

type SONInformationExtensionIEIEValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowSONInformationReport *SONInformationReport
}

func (v SONInformationExtensionIEIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(206):
		return v.rowSONInformationReport != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SONInformationExtensionIEIEValue and reports whether the opaque alternative is selected.
func (v *SONInformationExtensionIEIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SONInformationExtensionIEIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE"}}
}
func (SONInformationExtensionIEIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(206):
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

// AsSONInformationReport returns the selected SONInformationReport value of SONInformationExtensionIEIEValue and reports whether that alternative is active.
func (v *SONInformationExtensionIEIEValue) AsSONInformationReport() (*SONInformationReport, bool) {
	if v == nil || v.id != s00.ProtocolIEID(206) || v.rowSONInformationReport == nil {
		return nil, false
	}
	return v.rowSONInformationReport, true
}
func (v SONInformationExtensionIEIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SONInformationExtensionIEIEValue, error) {
	out := SONInformationExtensionIEIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(206):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SONInformationReport
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SONInformationReport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SONInformationReport")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSONInformationReport = &value
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
func (v SONInformationExtensionIEIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v SONInformationExtensionIEIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(206):
		if v.rowSONInformationReport == nil {
			return nil, fmt.Errorf("%s missing value", "SONInformation-ExtensionIE.id-SON-Information-Report:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSONInformationReport.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SONInformationExtensionIEIEValue:", v.id)
	}
}

type ERABToBeModifyItemBearerModReqExtIEsValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowTransportInformation *TransportInformation
}

func (v ERABToBeModifyItemBearerModReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(185):
		return v.rowTransportInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeModifyItemBearerModReqExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeModifyItemBearerModReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeModifyItemBearerModReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs"}}
}
func (ERABToBeModifyItemBearerModReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(185):
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

// AsTransportInformation returns the selected TransportInformation value of ERABToBeModifyItemBearerModReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeModifyItemBearerModReqExtIEsValue) AsTransportInformation() (*TransportInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(185) || v.rowTransportInformation == nil {
		return nil, false
	}
	return v.rowTransportInformation, true
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeModifyItemBearerModReqExtIEsValue, error) {
	out := ERABToBeModifyItemBearerModReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(185):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TransportInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TransportInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TransportInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTransportInformation = &value
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
func (v ERABToBeModifyItemBearerModReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(185):
		if v.rowTransportInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeModifyItemBearerModReqExtIEs.id-TransportInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTransportInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeModifyItemBearerModReqExtIEsValue:", v.id)
	}
}

type S1RemovalRequestIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowGlobalENBID *s21.GlobalENBID
}

func (v S1RemovalRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(59):
		return v.rowGlobalENBID != nil
	}
	return false
}

// Opaque returns the retained opaque open value of S1RemovalRequestIEValue and reports whether the opaque alternative is selected.
func (v *S1RemovalRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1RemovalRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs"}}
}
func (S1RemovalRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(59):
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

// AsGlobalENBID returns the selected GlobalENBID value of S1RemovalRequestIEValue and reports whether that alternative is active.
func (v *S1RemovalRequestIEValue) AsGlobalENBID() (*s21.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}
func (v S1RemovalRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1RemovalRequestIEValue, error) {
	out := S1RemovalRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(59):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s21.GlobalENBID
		child := scope
		if err := s21.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GlobalENBID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalENBID")
		if err != nil {
			return out, err
		}
		*s21.BridgeGlobalENBIDFieldPerPadding(&value) = padding
		*s21.BridgeGlobalENBIDFieldReceived(&value) = true
		raw.RetainContents(s21.BridgeGlobalENBIDFieldReceivedBytes(&value))
		*s21.BridgeGlobalENBIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowGlobalENBID = &value
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
func (v S1RemovalRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1RemovalRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(59):
		if v.rowGlobalENBID == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalRequestIEs.id-Global-ENB-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s21.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1RemovalRequestIEValue:", v.id)
	}
}

type TraceFailureIndicationIEValue struct {
	id               s00.ProtocolIEID
	received         aper.WireSpan
	replay           aper.Snapshot
	opaque           aper.OpaqueOpenType
	isOpaque         bool
	rowMMEUES1APID   *s00.MMEUES1APID
	rowENBUES1APID   *s00.ENBUES1APID
	rowEUTRANTraceID *s00.EUTRANTraceID
	rowCause         *s17.Cause
}

func (v TraceFailureIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of TraceFailureIndicationIEValue and reports whether the opaque alternative is selected.
func (v *TraceFailureIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (TraceFailureIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs"}}
}
func (TraceFailureIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(86):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of TraceFailureIndicationIEValue and reports whether that alternative is active.
func (v *TraceFailureIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of TraceFailureIndicationIEValue and reports whether that alternative is active.
func (v *TraceFailureIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsEUTRANTraceID returns the selected EUTRANTraceID value of TraceFailureIndicationIEValue and reports whether that alternative is active.
func (v *TraceFailureIndicationIEValue) AsEUTRANTraceID() (*s00.EUTRANTraceID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(86) || v.rowEUTRANTraceID == nil {
		return nil, false
	}
	return v.rowEUTRANTraceID, true
}

// AsCause returns the selected Cause value of TraceFailureIndicationIEValue and reports whether that alternative is active.
func (v *TraceFailureIndicationIEValue) AsCause() (*s17.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v TraceFailureIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TraceFailureIndicationIEValue, error) {
	out := TraceFailureIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.Cause
		child := scope
		if err := s17.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s17.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s17.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCauseFieldReceivedBytes(&value))
		*s17.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
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
func (v TraceFailureIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v TraceFailureIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "TraceFailureIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "TraceFailureIndicationIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "TraceFailureIndicationIEs.id-E-UTRAN-Trace-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "TraceFailureIndicationIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TraceFailureIndicationIEValue:", v.id)
	}
}

type UEContextModificationIndicationIEValue struct {
	id                   s00.ProtocolIEID
	received             aper.WireSpan
	replay               aper.Snapshot
	opaque               aper.OpaqueOpenType
	isOpaque             bool
	rowMMEUES1APID       *s00.MMEUES1APID
	rowENBUES1APID       *s00.ENBUES1APID
	rowCSGMembershipInfo *s17.CSGMembershipInfo
}

func (v UEContextModificationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(226):
		return v.rowCSGMembershipInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextModificationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *UEContextModificationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs"}}
}
func (UEContextModificationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(226):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCSGMembershipInfo returns the selected CSGMembershipInfo value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsCSGMembershipInfo() (*s17.CSGMembershipInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(226) || v.rowCSGMembershipInfo == nil {
		return nil, false
	}
	return v.rowCSGMembershipInfo, true
}
func (v UEContextModificationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationIndicationIEValue, error) {
	out := UEContextModificationIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(226):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.CSGMembershipInfo
		child := scope
		if err := s17.BridgeCSGMembershipInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CSGMembershipInfo")
		if err != nil {
			return out, err
		}
		*s17.BridgeCSGMembershipInfoFieldPerPadding(&value) = padding
		*s17.BridgeCSGMembershipInfoFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCSGMembershipInfoFieldReceivedBytes(&value))
		*s17.BridgeCSGMembershipInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCSGMembershipInfo = &value
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
func (v UEContextModificationIndicationIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(226):
		if v.rowCSGMembershipInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-CSGMembershipInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeCSGMembershipInfoMethodMarshalAPERBudget(v.rowCSGMembershipInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationIndicationIEValue:", v.id)
	}
}

type UplinkS1cdma2000tunnellingIEValue struct {
	id                                    s00.ProtocolIEID
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                aper.OpaqueOpenType
	isOpaque                              bool
	rowMMEUES1APID                        *s00.MMEUES1APID
	rowENBUES1APID                        *s00.ENBUES1APID
	rowCdma2000RATType                    *s00.Cdma2000RATType
	rowCdma2000SectorID                   *s00.Cdma2000SectorID
	rowCdma2000HORequiredIndication       *s00.Cdma2000HORequiredIndication
	rowCdma2000OneXSRVCCInfo              *s17.Cdma2000OneXSRVCCInfo
	rowCdma2000OneXRAND                   *s00.Cdma2000OneXRAND
	rowCdma2000PDU                        *s00.Cdma2000PDU
	rowEUTRANRoundTripDelayEstimationInfo *s00.EUTRANRoundTripDelayEstimationInfo
}

func (v UplinkS1cdma2000tunnellingIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(71):
		return v.rowCdma2000RATType != nil
	case s00.ProtocolIEID(72):
		return v.rowCdma2000SectorID != nil
	case s00.ProtocolIEID(84):
		return v.rowCdma2000HORequiredIndication != nil
	case s00.ProtocolIEID(102):
		return v.rowCdma2000OneXSRVCCInfo != nil
	case s00.ProtocolIEID(97):
		return v.rowCdma2000OneXRAND != nil
	case s00.ProtocolIEID(70):
		return v.rowCdma2000PDU != nil
	case s00.ProtocolIEID(140):
		return v.rowEUTRANRoundTripDelayEstimationInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UplinkS1cdma2000tunnellingIEValue and reports whether the opaque alternative is selected.
func (v *UplinkS1cdma2000tunnellingIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UplinkS1cdma2000tunnellingIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs"}}
}
func (UplinkS1cdma2000tunnellingIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(71):
		return aper.UnknownSelector
	case s00.ProtocolIEID(72):
		return aper.UnknownSelector
	case s00.ProtocolIEID(84):
		return aper.UnknownSelector
	case s00.ProtocolIEID(102):
		return aper.UnknownSelector
	case s00.ProtocolIEID(97):
		return aper.UnknownSelector
	case s00.ProtocolIEID(70):
		return aper.UnknownSelector
	case s00.ProtocolIEID(140):
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
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCdma2000RATType returns the selected Cdma2000RATType value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000RATType() (*s00.Cdma2000RATType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(71) || v.rowCdma2000RATType == nil {
		return nil, false
	}
	return v.rowCdma2000RATType, true
}

// AsCdma2000SectorID returns the selected Cdma2000SectorID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000SectorID() (*s00.Cdma2000SectorID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(72) || v.rowCdma2000SectorID == nil {
		return nil, false
	}
	return v.rowCdma2000SectorID, true
}

// AsCdma2000HORequiredIndication returns the selected Cdma2000HORequiredIndication value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000HORequiredIndication() (*s00.Cdma2000HORequiredIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(84) || v.rowCdma2000HORequiredIndication == nil {
		return nil, false
	}
	return v.rowCdma2000HORequiredIndication, true
}

// AsCdma2000OneXSRVCCInfo returns the selected Cdma2000OneXSRVCCInfo value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000OneXSRVCCInfo() (*s17.Cdma2000OneXSRVCCInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(102) || v.rowCdma2000OneXSRVCCInfo == nil {
		return nil, false
	}
	return v.rowCdma2000OneXSRVCCInfo, true
}

// AsCdma2000OneXRAND returns the selected Cdma2000OneXRAND value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000OneXRAND() (*s00.Cdma2000OneXRAND, bool) {
	if v == nil || v.id != s00.ProtocolIEID(97) || v.rowCdma2000OneXRAND == nil {
		return nil, false
	}
	return v.rowCdma2000OneXRAND, true
}

// AsCdma2000PDU returns the selected Cdma2000PDU value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000PDU() (*s00.Cdma2000PDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(70) || v.rowCdma2000PDU == nil {
		return nil, false
	}
	return v.rowCdma2000PDU, true
}

// AsEUTRANRoundTripDelayEstimationInfo returns the selected EUTRANRoundTripDelayEstimationInfo value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsEUTRANRoundTripDelayEstimationInfo() (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(140) || v.rowEUTRANRoundTripDelayEstimationInfo == nil {
		return nil, false
	}
	return v.rowEUTRANRoundTripDelayEstimationInfo, true
}
func (v UplinkS1cdma2000tunnellingIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UplinkS1cdma2000tunnellingIEValue, error) {
	out := UplinkS1cdma2000tunnellingIEValue{id: id}
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
	case s00.ProtocolIEID(71):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Cdma2000RATType"})
		value := s00.Cdma2000RATType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000RATType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCdma2000RATType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(72):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000SectorID, error) {
			var v struct{ Value s00.Cdma2000SectorID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000SectorID(val_value)
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
		out.rowCdma2000SectorID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(84):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Cdma2000HORequiredIndication"})
		value := s00.Cdma2000HORequiredIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000HORequiredIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCdma2000HORequiredIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(102):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.Cdma2000OneXSRVCCInfo
		child := scope
		if err := s17.BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000OneXSRVCCInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cdma2000OneXSRVCCInfo")
		if err != nil {
			return out, err
		}
		*s17.BridgeCdma2000OneXSRVCCInfoFieldPerPadding(&value) = padding
		*s17.BridgeCdma2000OneXSRVCCInfoFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCdma2000OneXSRVCCInfoFieldReceivedBytes(&value))
		*s17.BridgeCdma2000OneXSRVCCInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCdma2000OneXSRVCCInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(97):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000OneXRAND, error) {
			var v struct{ Value s00.Cdma2000OneXRAND }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000OneXRAND(val_value)
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
		out.rowCdma2000OneXRAND = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(70):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000PDU, error) {
			var v struct{ Value s00.Cdma2000PDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000PDU(val_value)
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
		out.rowCdma2000PDU = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(140):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(2047), false)
		value := s00.EUTRANRoundTripDelayEstimationInfo(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANRoundTripDelayEstimationInfo:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEUTRANRoundTripDelayEstimationInfo = &value
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
func (v UplinkS1cdma2000tunnellingIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UplinkS1cdma2000tunnellingIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(71):
		if v.rowCdma2000RATType == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000RATType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCdma2000RATType), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(72):
		if v.rowCdma2000SectorID == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000SectorID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000SectorID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000SectorID }{Value: value}
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
		})(*v.rowCdma2000SectorID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(84):
		if v.rowCdma2000HORequiredIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000HORequiredIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCdma2000HORequiredIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(102):
		if v.rowCdma2000OneXSRVCCInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXSRVCCInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERBudget(v.rowCdma2000OneXSRVCCInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(97):
		if v.rowCdma2000OneXRAND == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXRAND:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000OneXRAND, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000OneXRAND }{Value: value}
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
		})(*v.rowCdma2000OneXRAND, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(70):
		if v.rowCdma2000PDU == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000PDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000PDU }{Value: value}
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
		})(*v.rowCdma2000PDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(140):
		if v.rowEUTRANRoundTripDelayEstimationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-EUTRANRoundTripDelayEstimationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowEUTRANRoundTripDelayEstimationInfo), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(2047), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UplinkS1cdma2000tunnellingIEValue:", v.id)
	}
}

type SONInformationExtensionIETable struct{}

func SONInformationExtensionIE() SONInformationExtensionIETable {
	return SONInformationExtensionIETable{}
}

// ID returns the ASN.1 object-set identity of SONInformationExtensionIETable.
func (SONInformationExtensionIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SONInformationExtensionIETable.
func (SONInformationExtensionIETable) Table() s00.SONInformationExtensionIEIEValueIETable {
	return func() s00.SONInformationExtensionIEIEValueIETable {
		sealed := s00.SONInformationExtensionIEIEValueIETable{}
		*s00.BridgeSONInformationExtensionIEIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SONInformationExtensionIETable) infoSONInformationReport() s00.FieldInfo {
	return s00.FieldInfo{Table: SONInformationExtensionIE().ID(), ID: s00.ProtocolIEID(206), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReport"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE", Row: "id-SON-Information-Report"}}}
}

// SONInformationReport returns the typed binding for the SONInformationReport row of SONInformationExtensionIETable.
func (t SONInformationExtensionIETable) SONInformationReport() SONInformationExtensionIESONInformationReportIEBinding {
	return SONInformationExtensionIESONInformationReportIEBinding{info: t.infoSONInformationReport(), codec: SONInformationReportValueCodec{path: "SONInformationReport",
		decode: func(data []byte, options aper.DecodeState) (SONInformationReport, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SONInformationReport
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SONInformationReport")
			var zero SONInformationExtensionIEIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(206), raw)
			if err != nil {
				var empty SONInformationReport
				return empty, runtime.WrapDecodePath(err, "SONInformationReport")
			}
			value, ok := decoded.AsSONInformationReport()
			if !ok {
				var empty SONInformationReport
				return empty, fmt.Errorf("binding SONInformation-ExtensionIE.id-SON-Information-Report: no selected value")
			}
			return *value, nil
		},
		encode: func(value SONInformationReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONInformationExtensionIEIEValue{id: s00.ProtocolIEID(206), rowSONInformationReport: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SONInformationReport, options aper.DecodeState) (SONInformationReport, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSONInformationReport(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SONInformationReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSONInformationReport(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationReport"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SONInformationReport) SONInformationExtensionIEIEValue {
		return SONInformationExtensionIEIEValue{id: s00.ProtocolIEID(206), rowSONInformationReport: &value}
	}, get: func(value *SONInformationExtensionIEIEValue) (*SONInformationReport, bool) {
		return value.AsSONInformationReport()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SONInformationExtensionIETable.
func (t SONInformationExtensionIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SONInformationExtensionIEIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(206):
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("known IE id-SON-Information-Report requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		return SONInformationExtensionIEIEField{Id: id, Criticality: criticality, Value: SONInformationExtensionIEIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeModifyItemBearerModReqExtIETable struct{}

func ERABToBeModifyItemBearerModReqExtIEs() ERABToBeModifyItemBearerModReqExtIETable {
	return ERABToBeModifyItemBearerModReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeModifyItemBearerModReqExtIETable.
func (ERABToBeModifyItemBearerModReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeModifyItemBearerModReqExtIETable.
func (ERABToBeModifyItemBearerModReqExtIETable) Table() s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable {
	return func() s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable {
		sealed := s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeModifyItemBearerModReqExtIETable) infoTransportInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeModifyItemBearerModReqExtIEs().ID(), ID: s00.ProtocolExtensionID(185), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs", Row: "id-TransportInformation"}}}
}

// TransportInformation returns the typed binding for the TransportInformation row of ERABToBeModifyItemBearerModReqExtIETable.
func (t ERABToBeModifyItemBearerModReqExtIETable) TransportInformation() ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding {
	return ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding{info: t.infoTransportInformation(), codec: TransportInformationValueCodec{path: "TransportInformation",
		decode: func(data []byte, options aper.DecodeState) (TransportInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TransportInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportInformation")
			var zero ERABToBeModifyItemBearerModReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(185), raw)
			if err != nil {
				var empty TransportInformation
				return empty, runtime.WrapDecodePath(err, "TransportInformation")
			}
			value, ok := decoded.AsTransportInformation()
			if !ok {
				var empty TransportInformation
				return empty, fmt.Errorf("binding E-RABToBeModifyItemBearerModReqExtIEs.id-TransportInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value TransportInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeModifyItemBearerModReqExtIEsValue{id: s00.ProtocolIEID(185), rowTransportInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TransportInformation, options aper.DecodeState) (TransportInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APTransportInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v TransportInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTransportInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TransportInformation) ERABToBeModifyItemBearerModReqExtIEsValue {
		return ERABToBeModifyItemBearerModReqExtIEsValue{id: s00.ProtocolIEID(185), rowTransportInformation: &value}
	}, get: func(value *ERABToBeModifyItemBearerModReqExtIEsValue) (*TransportInformation, bool) {
		return value.AsTransportInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeModifyItemBearerModReqExtIETable.
func (t ERABToBeModifyItemBearerModReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(185):
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-TransportInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeModifyItemBearerModReqExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type RerouteNASRequestIETable struct{}

func RerouteNASRequestIEs() RerouteNASRequestIETable { return RerouteNASRequestIETable{} }

// ID returns the ASN.1 object-set identity of RerouteNASRequestIETable.
func (RerouteNASRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RerouteNASRequestIETable.
func (RerouteNASRequestIETable) Table() s00.RerouteNASRequestIEValueIETable {
	return func() s00.RerouteNASRequestIEValueIETable {
		sealed := s00.RerouteNASRequestIEValueIETable{}
		*s00.BridgeRerouteNASRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RerouteNASRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) ENBUES1APID() s23.RerouteNASRequestENBUES1APIDIEBinding {
	return func() s23.RerouteNASRequestENBUES1APIDIEBinding {
		sealed := s23.RerouteNASRequestENBUES1APIDIEBinding{}
		*s23.BridgeRerouteNASRequestENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s23.BridgeRerouteNASRequestENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s23.RerouteNASRequestIEValue
				decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
					sealed := s23.RerouteNASRequestIEValue{}
					*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s23.BridgeRerouteNASRequestIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s23.BridgeRerouteNASRequestENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeRerouteNASRequestIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s23.BridgeRerouteNASRequestENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s23.RerouteNASRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (RerouteNASRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) MMEUES1APID() RerouteNASRequestMMEUES1APIDIEBinding {
	return RerouteNASRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero s23.RerouteNASRequestIEValue
			decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		inject: func(value s00.MMEUES1APID) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.RerouteNASRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (RerouteNASRequestIETable) infoS1Message() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(225), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OCTET STRING"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-S1-Message"}}}
}

// S1Message returns the typed binding for the S1Message row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) S1Message() RerouteNASRequestSliceByteIEBinding {
	return RerouteNASRequestSliceByteIEBinding{info: t.infoS1Message(), codec: func() s02.SliceByteValueCodec {
		sealed := s02.SliceByteValueCodec{}
		*s02.BridgeSliceByteValueCodecFieldPath(&sealed) = "[]byte"
		*s02.BridgeSliceByteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) ([]byte, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty []byte
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("[]byte")
			var zero s23.RerouteNASRequestIEValue
			decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(225), raw)
			if err != nil {
				var empty []byte
				return empty, runtime.WrapDecodePath(err, "[]byte")
			}
			value, ok := decoded.AsS1Message()
			if !ok {
				var empty []byte
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-S1-Message: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSliceByteValueCodecFieldEncode(&sealed) = func(value []byte, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(225)
				*s23.BridgeRerouteNASRequestIEValueFieldRowS1Message(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s02.BridgeSliceByteValueCodecFieldCapture(&sealed) = func(v []byte, options aper.DecodeState) ([]byte, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			func(v *[]byte, s *aper.SemanticCapture) {
				if s.Err() != nil {
					return
				}
				f := s.Begin()
				s.Bytes((*v))
				s.End(
					f, nil, false)
			}(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s02.BridgeSliceByteValueCodecFieldCompare(&sealed) = func(v []byte, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			func(v *[]byte, s *aper.SemanticComparison) {
				if s.Err() != nil {
					return

				}
				f := s.Begin()
				s.Bytes((*v))
				s.End(f, aper.Snapshot{}, false)
			}(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSliceByteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:[]byte"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value []byte) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(225)
				*s23.BridgeRerouteNASRequestIEValueFieldRowS1Message(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.RerouteNASRequestIEValue) (*[]byte, bool) { return value.AsS1Message() }}
}
func (RerouteNASRequestIETable) infoMMEGroupID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(223), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-Group-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-MME-Group-ID"}}}
}

// MMEGroupID returns the typed binding for the MMEGroupID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) MMEGroupID() RerouteNASRequestMMEGroupIDIEBinding {
	return RerouteNASRequestMMEGroupIDIEBinding{info: t.infoMMEGroupID(), codec: func() s01.MMEGroupIDValueCodec {
		sealed := s01.MMEGroupIDValueCodec{}
		*s01.BridgeMMEGroupIDValueCodecFieldPath(&sealed) = "MMEGroupID"
		*s01.BridgeMMEGroupIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEGroupID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEGroupID")
			var zero s23.RerouteNASRequestIEValue
			decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(223), raw)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, runtime.WrapDecodePath(err, "MMEGroupID")
			}
			value, ok := decoded.AsMMEGroupID()
			if !ok {
				var empty s00.MMEGroupID
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-MME-Group-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEGroupIDValueCodecFieldEncode(&sealed) = func(value s00.MMEGroupID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEGroupID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCapture(&sealed) = func(v s00.MMEGroupID, options aper.DecodeState) (s00.MMEGroupID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEGroupID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCompare(&sealed) = func(v s00.MMEGroupID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEGroupID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEGroupIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEGroupID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEGroupID) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEGroupID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.RerouteNASRequestIEValue) (*s00.MMEGroupID, bool) { return value.AsMMEGroupID() }}
}
func (RerouteNASRequestIETable) infoAdditionalGUTI() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(224), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Additional-GUTI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-Additional-GUTI"}}}
}

// AdditionalGUTI returns the typed binding for the AdditionalGUTI row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) AdditionalGUTI() s23.RerouteNASRequestAdditionalGUTIIEBinding {
	return func() s23.RerouteNASRequestAdditionalGUTIIEBinding {
		sealed := s23.RerouteNASRequestAdditionalGUTIIEBinding{}
		*s23.BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldInfo(&sealed) = t.infoAdditionalGUTI()
		*s23.BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldCodec(&sealed) = func() s21.AdditionalGUTIValueCodec {
			sealed := s21.AdditionalGUTIValueCodec{}
			*s21.BridgeAdditionalGUTIValueCodecFieldPath(&sealed) = "AdditionalGUTI"
			*s21.BridgeAdditionalGUTIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.AdditionalGUTI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s21.AdditionalGUTI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AdditionalGUTI")
				var zero s23.RerouteNASRequestIEValue
				decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(224), raw)
				if err != nil {
					var empty s21.AdditionalGUTI
					return empty, runtime.WrapDecodePath(err, "AdditionalGUTI")
				}
				value, ok := decoded.AsAdditionalGUTI()
				if !ok {
					var empty s21.AdditionalGUTI
					return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-Additional-GUTI: no selected value")
				}
				return *value, nil
			}
			*s21.BridgeAdditionalGUTIValueCodecFieldEncode(&sealed) = func(value s21.AdditionalGUTI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
					sealed := s23.RerouteNASRequestIEValue{}
					*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(224)
					*s23.BridgeRerouteNASRequestIEValueFieldRowAdditionalGUTI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s21.BridgeAdditionalGUTIValueCodecFieldCapture(&sealed) = func(v s21.AdditionalGUTI, options aper.DecodeState) (s21.AdditionalGUTI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s21.BridgeCaptureS1APAdditionalGUTI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s21.BridgeAdditionalGUTIValueCodecFieldCompare(&sealed) = func(v s21.AdditionalGUTI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s21.BridgeCompareS1APAdditionalGUTI(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s21.BridgeAdditionalGUTIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalGUTI"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s23.BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldInject(&sealed) = func(value s21.AdditionalGUTI) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(224)
				*s23.BridgeRerouteNASRequestIEValueFieldRowAdditionalGUTI(&sealed) = &value
				return sealed
			}()
		}
		*s23.BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldGet(&sealed) = func(value *s23.RerouteNASRequestIEValue) (*s21.AdditionalGUTI, bool) {
			return value.AsAdditionalGUTI()
		}
		return sealed
	}()
}
func (RerouteNASRequestIETable) infoUEUsageType() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(230), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Usage-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-UE-Usage-Type"}}}
}

// UEUsageType returns the typed binding for the UEUsageType row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) UEUsageType() RerouteNASRequestUEUsageTypeIEBinding {
	return RerouteNASRequestUEUsageTypeIEBinding{info: t.infoUEUsageType(), codec: func() s02.UEUsageTypeValueCodec {
		sealed := s02.UEUsageTypeValueCodec{}
		*s02.BridgeUEUsageTypeValueCodecFieldPath(&sealed) = "UEUsageType"
		*s02.BridgeUEUsageTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUsageType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUsageType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEUsageType")
			var zero s23.RerouteNASRequestIEValue
			decoded, err := s23.BridgeRerouteNASRequestIEValueMethodDecode(zero, s00.ProtocolIEID(230), raw)
			if err != nil {
				var empty s00.UEUsageType
				return empty, runtime.WrapDecodePath(err, "UEUsageType")
			}
			value, ok := decoded.AsUEUsageType()
			if !ok {
				var empty s00.UEUsageType
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-UE-Usage-Type: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUsageTypeValueCodecFieldEncode(&sealed) = func(value s00.UEUsageType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s23.BridgeRerouteNASRequestIEValueMethodEncodeFresh((func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s23.BridgeRerouteNASRequestIEValueFieldRowUEUsageType(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCapture(&sealed) = func(v s00.UEUsageType, options aper.DecodeState) (s00.UEUsageType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEUsageType(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCompare(&sealed) = func(v s00.UEUsageType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APUEUsageType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeUEUsageTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUsageType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEUsageType) s23.RerouteNASRequestIEValue {
			return func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s23.BridgeRerouteNASRequestIEValueFieldRowUEUsageType(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s23.RerouteNASRequestIEValue) (*s00.UEUsageType, bool) { return value.AsUEUsageType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s23.RerouteNASRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(0):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(225):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-S1-Message requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(223):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-Group-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(224):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Additional-GUTI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(230):
		return s23.RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Usage-Type requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s23.RerouteNASRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return s23.RerouteNASRequestIEField{Id: id, Criticality: criticality, Value: func() s23.RerouteNASRequestIEValue {
			sealed := s23.RerouteNASRequestIEValue{}
			*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = id
			*s23.BridgeRerouteNASRequestIEValueFieldOpaque(&sealed) = opaque
			*s23.BridgeRerouteNASRequestIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type S1RemovalRequestIETable struct{}

func S1RemovalRequestIEs() S1RemovalRequestIETable { return S1RemovalRequestIETable{} }

// ID returns the ASN.1 object-set identity of S1RemovalRequestIETable.
func (S1RemovalRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by S1RemovalRequestIETable.
func (S1RemovalRequestIETable) Table() s00.S1RemovalRequestIEValueIETable {
	return func() s00.S1RemovalRequestIEValueIETable {
		sealed := s00.S1RemovalRequestIEValueIETable{}
		*s00.BridgeS1RemovalRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1RemovalRequestIETable) infoGlobalENBID() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalRequestIEs().ID(), ID: s00.ProtocolIEID(59), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-ENB-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs", Row: "id-Global-ENB-ID"}}}
}

// GlobalENBID returns the typed binding for the GlobalENBID row of S1RemovalRequestIETable.
func (t S1RemovalRequestIETable) GlobalENBID() S1RemovalRequestGlobalENBIDIEBinding {
	return S1RemovalRequestGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s21.GlobalENBIDValueCodec {
		sealed := s21.GlobalENBIDValueCodec{}
		*s21.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s21.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero S1RemovalRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s21.GlobalENBID
				return empty, fmt.Errorf("binding S1RemovalRequestIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s21.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s21.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
		}
		*s21.BridgeGlobalENBIDValueCodecFieldCapture(&sealed) = func(v s21.GlobalENBID, options aper.DecodeState) (s21.GlobalENBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APGlobalENBID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeGlobalENBIDValueCodecFieldCompare(&sealed) = func(v s21.GlobalENBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APGlobalENBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s21.BridgeGlobalENBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalENBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s21.GlobalENBID) S1RemovalRequestIEValue {
			return S1RemovalRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *S1RemovalRequestIEValue) (*s21.GlobalENBID, bool) { return value.AsGlobalENBID() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in S1RemovalRequestIETable.
func (t S1RemovalRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1RemovalRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(59):
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Global-ENB-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1RemovalRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1RemovalRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1RemovalRequestIEField{Id: id, Criticality: criticality, Value: S1RemovalRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type TraceFailureIndicationIETable struct{}

func TraceFailureIndicationIEs() TraceFailureIndicationIETable {
	return TraceFailureIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of TraceFailureIndicationIETable.
func (TraceFailureIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TraceFailureIndicationIETable.
func (TraceFailureIndicationIETable) Table() s00.TraceFailureIndicationIEValueIETable {
	return func() s00.TraceFailureIndicationIEValueIETable {
		sealed := s00.TraceFailureIndicationIEValueIETable{}
		*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TraceFailureIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) MMEUES1APID() TraceFailureIndicationMMEUES1APIDIEBinding {
	return TraceFailureIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero TraceFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) TraceFailureIndicationIEValue {
			return TraceFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *TraceFailureIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (TraceFailureIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) ENBUES1APID() TraceFailureIndicationENBUES1APIDIEBinding {
	return TraceFailureIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero TraceFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceFailureIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) TraceFailureIndicationIEValue {
			return TraceFailureIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *TraceFailureIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (TraceFailureIndicationIETable) infoEUTRANTraceID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(86), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-UTRAN-Trace-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-E-UTRAN-Trace-ID"}}}
}

// EUTRANTraceID returns the typed binding for the EUTRANTraceID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) EUTRANTraceID() TraceFailureIndicationEUTRANTraceIDIEBinding {
	return TraceFailureIndicationEUTRANTraceIDIEBinding{info: t.infoEUTRANTraceID(), codec: func() s00.EUTRANTraceIDValueCodec {
		sealed := s00.EUTRANTraceIDValueCodec{}
		*s00.BridgeEUTRANTraceIDValueCodecFieldPath(&sealed) = "EUTRANTraceID"
		*s00.BridgeEUTRANTraceIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANTraceID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EUTRANTraceID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANTraceID")
			var zero TraceFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(86), raw)
			if err != nil {
				var empty s00.EUTRANTraceID
				return empty, runtime.WrapDecodePath(err, "EUTRANTraceID")
			}
			value, ok := decoded.AsEUTRANTraceID()
			if !ok {
				var empty s00.EUTRANTraceID
				return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-E-UTRAN-Trace-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&sealed) = func(value s00.EUTRANTraceID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceFailureIndicationIEValue{id: s00.ProtocolIEID(86), rowEUTRANTraceID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.EUTRANTraceID) TraceFailureIndicationIEValue {
			return TraceFailureIndicationIEValue{id: s00.ProtocolIEID(86), rowEUTRANTraceID: &value}
		}, get: func(value *TraceFailureIndicationIEValue) (*s00.EUTRANTraceID, bool) { return value.AsEUTRANTraceID() }}
}
func (TraceFailureIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) Cause() TraceFailureIndicationCauseIEBinding {
	return TraceFailureIndicationCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero TraceFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s17.Cause, options aper.DecodeState) (s17.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s17.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s17.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.Cause) TraceFailureIndicationIEValue {
			return TraceFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *TraceFailureIndicationIEValue) (*s17.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (TraceFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(86):
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-UTRAN-Trace-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TraceFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TraceFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return TraceFailureIndicationIEField{Id: id, Criticality: criticality, Value: TraceFailureIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationIndicationIETable struct{}

func UEContextModificationIndicationIEs() UEContextModificationIndicationIETable {
	return UEContextModificationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextModificationIndicationIETable.
func (UEContextModificationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextModificationIndicationIETable.
func (UEContextModificationIndicationIETable) Table() s00.UEContextModificationIndicationIEValueIETable {
	return func() s00.UEContextModificationIndicationIEValueIETable {
		sealed := s00.UEContextModificationIndicationIEValueIETable{}
		*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) MMEUES1APID() UEContextModificationIndicationMMEUES1APIDIEBinding {
	return UEContextModificationIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) ENBUES1APID() UEContextModificationIndicationENBUES1APIDIEBinding {
	return UEContextModificationIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationIndicationIETable) infoCSGMembershipInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(226), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-CSGMembershipInfo"}}}
}

// CSGMembershipInfo returns the typed binding for the CSGMembershipInfo row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) CSGMembershipInfo() UEContextModificationIndicationCSGMembershipInfoIEBinding {
	return UEContextModificationIndicationCSGMembershipInfoIEBinding{info: t.infoCSGMembershipInfo(), codec: func() s17.CSGMembershipInfoValueCodec {
		sealed := s17.CSGMembershipInfoValueCodec{}
		*s17.BridgeCSGMembershipInfoValueCodecFieldPath(&sealed) = "CSGMembershipInfo"
		*s17.BridgeCSGMembershipInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CSGMembershipInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.CSGMembershipInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipInfo")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(226), raw)
			if err != nil {
				var empty s17.CSGMembershipInfo
				return empty, runtime.WrapDecodePath(err, "CSGMembershipInfo")
			}
			value, ok := decoded.AsCSGMembershipInfo()
			if !ok {
				var empty s17.CSGMembershipInfo
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-CSGMembershipInfo: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCSGMembershipInfoValueCodecFieldEncode(&sealed) = func(value s17.CSGMembershipInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(226), rowCSGMembershipInfo: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCSGMembershipInfoValueCodecFieldCapture(&sealed) = func(v s17.CSGMembershipInfo, options aper.DecodeState) (s17.CSGMembershipInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCSGMembershipInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s17.BridgeCSGMembershipInfoValueCodecFieldCompare(&sealed) = func(v s17.CSGMembershipInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCSGMembershipInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeCSGMembershipInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.CSGMembershipInfo) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(226), rowCSGMembershipInfo: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s17.CSGMembershipInfo, bool) {
			return value.AsCSGMembershipInfo()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(226):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationIndicationIEField{Id: id, Criticality: criticality, Value: UEContextModificationIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AdditionalGUTICodec binds the complete APER value type.
func AdditionalGUTICodec() s21.AdditionalGUTIValueCodec {
	return RerouteNASRequestIEs().AdditionalGUTI().Codec()
}

// FailureEventReportCodec binds the complete source value type.
func FailureEventReportCodec() FailureEventReportValueCodec {
	return FailureEventReportValueCodec{path: "FailureEventReport", decode: func(data []byte, options aper.DecodeState) (FailureEventReport, error) {
		var value FailureEventReport
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return FailureEventReport{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value FailureEventReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v FailureEventReport, options aper.DecodeState) (FailureEventReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APFailureEventReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v FailureEventReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APFailureEventReport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FailureEventReport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONInformationExtensionCodec binds the complete source value type.
func SONInformationExtensionCodec() SONInformationExtensionValueCodec {
	return SONInformationExtensionValueCodec{path: "SONInformationExtension", decode: func(data []byte, options aper.DecodeState) (SONInformationExtension, error) {
		var value SONInformationExtension
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONInformationExtension{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONInformationExtension, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONInformationExtension, options aper.DecodeState) (SONInformationExtension, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONInformationExtension(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false,
		)
		return v, root
	}, compare: func(v SONInformationExtension, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONInformationExtension(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationExtension"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONInformationReportCodec binds the complete APER value type.
func SONInformationReportCodec() SONInformationReportValueCodec {
	return SONInformationExtensionIE().SONInformationReport().Codec()
}

// SONtransferCauseCodec binds the complete source value type.
func SONtransferCauseCodec() SONtransferCauseValueCodec {
	return SONtransferCauseValueCodec{path: "SONtransferCause", decode: func(data []byte, options aper.DecodeState) (SONtransferCause, error) {
		var value SONtransferCause
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferCause{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferCause, options aper.DecodeState) (SONtransferCause, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferCause(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONtransferCause(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferCause"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SourceNodeIDExtensionCodec binds the complete source value type.
func SourceNodeIDExtensionCodec() SourceNodeIDExtensionValueCodec {
	return SourceNodeIDExtensionValueCodec{path: "SourceNodeIDExtension", decode: func(data []byte, options aper.DecodeState) (SourceNodeIDExtension, error) {
		var value SourceNodeIDExtension
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SourceNodeIDExtension{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SourceNodeIDExtension, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SourceNodeIDExtension, options aper.DecodeState) (SourceNodeIDExtension, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSourceNodeIDExtension(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v SourceNodeIDExtension, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSourceNodeIDExtension(&v, &s)
		s.End(f, root, false)

		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNodeIDExtension"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TooEarlyInterRATHOReportReportFromEUTRANCodec binds the complete source value type.
func TooEarlyInterRATHOReportReportFromEUTRANCodec() TooEarlyInterRATHOReportReportFromEUTRANValueCodec {
	return TooEarlyInterRATHOReportReportFromEUTRANValueCodec{path: "TooEarlyInterRATHOReportReportFromEUTRAN", decode: func(data []byte, options aper.DecodeState) (TooEarlyInterRATHOReportReportFromEUTRAN, error) {
		var value TooEarlyInterRATHOReportReportFromEUTRAN
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TooEarlyInterRATHOReportReportFromEUTRAN{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TooEarlyInterRATHOReportReportFromEUTRAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TooEarlyInterRATHOReportReportFromEUTRAN, options aper.DecodeState) (TooEarlyInterRATHOReportReportFromEUTRAN, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTooEarlyInterRATHOReportReportFromEUTRAN(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TooEarlyInterRATHOReportReportFromEUTRAN, root aper.Snapshot, budget aper.DecodeBudget,
	) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		BridgeCompareS1APTooEarlyInterRATHOReportReportFromEUTRAN(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TooEarlyInterRATHOReportReportFromEUTRAN"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TransportInformationCodec binds the complete APER value type.
func TransportInformationCodec() TransportInformationValueCodec {
	return ERABToBeModifyItemBearerModReqExtIEs().TransportInformation().Codec()
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeModifyItemBearerModReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeModifyItemBearerModReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldId(v *ERABToBeModifyItemBearerModReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldIsOpaque(v *ERABToBeModifyItemBearerModReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldOpaque(v *ERABToBeModifyItemBearerModReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldRowTransportInformation(v *ERABToBeModifyItemBearerModReqExtIEsValue) **TransportInformation {
	return &v.rowTransportInformation
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCaptureSemantics(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeModifyItemBearerModReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCompareSemantics(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodMatchesID(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodRule(v ERABToBeModifyItemBearerModReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeFailureEventReportMethodMarshalAPERBudget(v *FailureEventReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeFailureEventReportMethodMarshalAPERTo(v *FailureEventReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeFailureEventReportMethodUnmarshalAPERFrom(v *FailureEventReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldCapture(v *RerouteNASRequestIEContainerValueCodec) *func(s23.RerouteNASRequestIEContainer, aper.DecodeState) (s23.RerouteNASRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldCompare(v *RerouteNASRequestIEContainerValueCodec) *func(s23.RerouteNASRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldContext(v *RerouteNASRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldDecode(v *RerouteNASRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (s23.RerouteNASRequestIEContainer, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldEncode(v *RerouteNASRequestIEContainerValueCodec) *func(s23.RerouteNASRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldPath(v *RerouteNASRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldCapture(v *RerouteNASRequestIEFieldValueCodec) *func(s23.RerouteNASRequestIEField, aper.DecodeState) (s23.RerouteNASRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldCompare(v *RerouteNASRequestIEFieldValueCodec) *func(s23.RerouteNASRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldContext(v *RerouteNASRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldDecode(v *RerouteNASRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (s23.RerouteNASRequestIEField, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldEncode(v *RerouteNASRequestIEFieldValueCodec) *func(s23.RerouteNASRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldPath(v *RerouteNASRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldCapture(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, aper.DecodeState) (S1RemovalRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldCompare(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldContext(v *S1RemovalRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldDecode(v *S1RemovalRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEContainer, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldEncode(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldPath(v *S1RemovalRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEFieldFieldReplay(v *S1RemovalRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEFieldFieldWithoutReplay(v *S1RemovalRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEFieldMethodMarshalAPERTo(v *S1RemovalRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1RemovalRequestIEFieldMethodUnmarshalAPERFrom(v *S1RemovalRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldCapture(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, aper.DecodeState) (S1RemovalRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldCompare(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldContext(v *S1RemovalRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldDecode(v *S1RemovalRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEField, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldEncode(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldPath(v *S1RemovalRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueFieldId(v *S1RemovalRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1RemovalRequestIEValueFieldIsOpaque(v *S1RemovalRequestIEValue) *bool       { return &v.isOpaque }
func BridgeS1RemovalRequestIEValueFieldOpaque(v *S1RemovalRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1RemovalRequestIEValueFieldRowGlobalENBID(v *S1RemovalRequestIEValue) **s21.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgeS1RemovalRequestIEValueMethodCaptureSemantics(v S1RemovalRequestIEValue, a0 aper.SemanticCapture) S1RemovalRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1RemovalRequestIEValueMethodCompareSemantics(v S1RemovalRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1RemovalRequestIEValueMethodMatchesID(v S1RemovalRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1RemovalRequestIEValueMethodRule(v S1RemovalRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldCapture(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, aper.DecodeState) (SONInformationExtensionIEIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldCompare(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldContext(v *SONInformationExtensionIEIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldDecode(v *SONInformationExtensionIEIEContainerValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEContainer, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldEncode(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldPath(v *SONInformationExtensionIEIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEFieldFieldReplay(v *SONInformationExtensionIEIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEFieldFieldWithoutReplay(v *SONInformationExtensionIEIEField) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEFieldMethodMarshalAPERTo(v *SONInformationExtensionIEIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationExtensionIEIEFieldMethodUnmarshalAPERFrom(v *SONInformationExtensionIEIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldCapture(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, aper.DecodeState) (SONInformationExtensionIEIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldCompare(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldContext(v *SONInformationExtensionIEIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldDecode(v *SONInformationExtensionIEIEFieldValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEField, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldEncode(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldPath(v *SONInformationExtensionIEIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueFieldId(v *SONInformationExtensionIEIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSONInformationExtensionIEIEValueFieldIsOpaque(v *SONInformationExtensionIEIEValue) *bool {
	return &v.isOpaque
}
func BridgeSONInformationExtensionIEIEValueFieldOpaque(v *SONInformationExtensionIEIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSONInformationExtensionIEIEValueFieldRowSONInformationReport(v *SONInformationExtensionIEIEValue) **SONInformationReport {
	return &v.rowSONInformationReport
}
func BridgeSONInformationExtensionIEIEValueMethodCaptureSemantics(v SONInformationExtensionIEIEValue, a0 aper.SemanticCapture) SONInformationExtensionIEIEValue {
	return v.captureSemantics(a0)
}
func BridgeSONInformationExtensionIEIEValueMethodCompareSemantics(v SONInformationExtensionIEIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionMethodMarshalAPERTo(v *SONInformationExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationExtensionMethodUnmarshalAPERFrom(v *SONInformationExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationReportMethodMarshalAPERBudget(v *SONInformationReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONtransferCauseMethodMarshalAPERBudget(v *SONtransferCause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERTo(v *SourceNodeIDExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNodeIDExtensionMethodUnmarshalAPERFrom(v *SourceNodeIDExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldCapture(v *TraceFailureIndicationIEContainerValueCodec) *func(TraceFailureIndicationIEContainer, aper.DecodeState) (TraceFailureIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldCompare(v *TraceFailureIndicationIEContainerValueCodec) *func(TraceFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldContext(v *TraceFailureIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(v *TraceFailureIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndicationIEContainer, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(v *TraceFailureIndicationIEContainerValueCodec) *func(TraceFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEContainerValueCodecFieldPath(v *TraceFailureIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationIEFieldFieldReplay(v *TraceFailureIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceFailureIndicationIEFieldFieldWithoutReplay(v *TraceFailureIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(v *TraceFailureIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(v *TraceFailureIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldCapture(v *TraceFailureIndicationIEFieldValueCodec) *func(TraceFailureIndicationIEField, aper.DecodeState) (TraceFailureIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldCompare(v *TraceFailureIndicationIEFieldValueCodec) *func(TraceFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldContext(v *TraceFailureIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldDecode(v *TraceFailureIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndicationIEField, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldEncode(v *TraceFailureIndicationIEFieldValueCodec) *func(TraceFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEFieldValueCodecFieldPath(v *TraceFailureIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *func(TraceFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *func(TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *func(TraceFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldPath(v *TraceFailureIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationIEValueFieldId(v *TraceFailureIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeTraceFailureIndicationIEValueFieldIsOpaque(v *TraceFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeTraceFailureIndicationIEValueFieldOpaque(v *TraceFailureIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeTraceFailureIndicationIEValueFieldRowCause(v *TraceFailureIndicationIEValue) **s17.Cause {
	return &v.rowCause
}
func BridgeTraceFailureIndicationIEValueFieldRowENBUES1APID(v *TraceFailureIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeTraceFailureIndicationIEValueFieldRowEUTRANTraceID(v *TraceFailureIndicationIEValue) **s00.EUTRANTraceID {
	return &v.rowEUTRANTraceID
}
func BridgeTraceFailureIndicationIEValueFieldRowMMEUES1APID(v *TraceFailureIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeTraceFailureIndicationIEValueMethodCaptureSemantics(v TraceFailureIndicationIEValue, a0 aper.SemanticCapture) TraceFailureIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeTraceFailureIndicationIEValueMethodCompareSemantics(v TraceFailureIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTraceFailureIndicationIEValueMethodMatchesID(v TraceFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeTraceFailureIndicationIEValueMethodRule(v TraceFailureIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(TraceFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldCapture(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, aper.DecodeState) (UEContextModificationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldCompare(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldContext(v *UEContextModificationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(v *UEContextModificationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldPath(v *UEContextModificationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEFieldFieldReplay(v *UEContextModificationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v *UEContextModificationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(v *UEContextModificationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldCapture(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, aper.DecodeState) (UEContextModificationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldCompare(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldContext(v *UEContextModificationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldDecode(v *UEContextModificationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldEncode(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldPath(v *UEContextModificationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueFieldId(v *UEContextModificationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationIndicationIEValueFieldIsOpaque(v *UEContextModificationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationIndicationIEValueFieldOpaque(v *UEContextModificationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationIndicationIEValueFieldRowCSGMembershipInfo(v *UEContextModificationIndicationIEValue) **s17.CSGMembershipInfo {
	return &v.rowCSGMembershipInfo
}
func BridgeUEContextModificationIndicationIEValueFieldRowENBUES1APID(v *UEContextModificationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationIndicationIEValueFieldRowMMEUES1APID(v *UEContextModificationIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationIndicationIEValueMethodCaptureSemantics(v UEContextModificationIndicationIEValue, a0 aper.SemanticCapture) UEContextModificationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationIndicationIEValueMethodCompareSemantics(v UEContextModificationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationIndicationIEValueMethodMatchesID(v UEContextModificationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationIndicationIEValueMethodRule(v UEContextModificationIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *s00.Cdma2000HORequiredIndicationValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HORequiredIndication, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *func(s00.Cdma2000HORequiredIndication) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *s00.Cdma2000OneXRANDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000OneXRAND, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *func(s00.Cdma2000OneXRAND) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *s17.Cdma2000OneXSRVCCInfoValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s17.Cdma2000OneXSRVCCInfo, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *func(s17.Cdma2000OneXSRVCCInfo) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.Cdma2000PDUValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(s00.Cdma2000PDU) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.Cdma2000RATTypeValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(s00.Cdma2000RATType) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *s00.Cdma2000SectorIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000SectorID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *func(s00.Cdma2000SectorID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldGet(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInject(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *func(s00.EUTRANRoundTripDelayEstimationInfo) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v *UplinkS1cdma2000tunnellingIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEField) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(v *UplinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(v *UplinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldId(v *UplinkS1cdma2000tunnellingIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldIsOpaque(v *UplinkS1cdma2000tunnellingIEValue) *bool {
	return &v.isOpaque
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldOpaque(v *UplinkS1cdma2000tunnellingIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000HORequiredIndication {
	return &v.rowCdma2000HORequiredIndication
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000OneXRAND {
	return &v.rowCdma2000OneXRAND
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(v *UplinkS1cdma2000tunnellingIEValue) **s17.Cdma2000OneXSRVCCInfo {
	return &v.rowCdma2000OneXSRVCCInfo
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000PDU {
	return &v.rowCdma2000PDU
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000RATType {
	return &v.rowCdma2000RATType
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000SectorID {
	return &v.rowCdma2000SectorID
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(v *UplinkS1cdma2000tunnellingIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(v *UplinkS1cdma2000tunnellingIEValue) **s00.EUTRANRoundTripDelayEstimationInfo {
	return &v.rowEUTRANRoundTripDelayEstimationInfo
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(v *UplinkS1cdma2000tunnellingIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodCaptureSemantics(v UplinkS1cdma2000tunnellingIEValue, a0 aper.SemanticCapture) UplinkS1cdma2000tunnellingIEValue {
	return v.captureSemantics(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodCompareSemantics(v UplinkS1cdma2000tunnellingIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(v UplinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UplinkS1cdma2000tunnellingIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh(v UplinkS1cdma2000tunnellingIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(v UplinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(v UplinkS1cdma2000tunnellingIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeModifyItemBearerModReqExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 185:
		if value, ok := v.AsTransportInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *S1RemovalRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 59:
		if value, ok := v.AsGlobalENBID(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SONInformationExtensionIEIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 206:
		if value, ok := v.AsSONInformationReport(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *TraceFailureIndicationIEValue) Selected() (any, bool) {
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
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UEContextModificationIndicationIEValue) Selected() (any, bool) {
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
	case 226:
		if value, ok := v.AsCSGMembershipInfo(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UplinkS1cdma2000tunnellingIEValue) Selected() (any, bool) {
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
	case 71:
		if value, ok := v.AsCdma2000RATType(); ok {
			return value, true
		}
	case 72:
		if value, ok := v.AsCdma2000SectorID(); ok {
			return value, true
		}
	case 84:
		if value, ok := v.AsCdma2000HORequiredIndication(); ok {
			return value, true
		}
	case 102:
		if value, ok := v.AsCdma2000OneXSRVCCInfo(); ok {
			return value, true
		}
	case 97:
		if value, ok := v.AsCdma2000OneXRAND(); ok {
			return value, true
		}
	case 70:
		if value, ok := v.AsCdma2000PDU(); ok {
			return value, true
		}
	case 140:
		if value, ok := v.AsEUTRANRoundTripDelayEstimationInfo(); ok {
			return value, true
		}
	}
	return nil, false
}
