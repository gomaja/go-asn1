// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s45 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s45

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ERABSetupResponseIEContainer is ProtocolIE-Container {{E-RABSetupResponseIEs}} of TS 36.413: a list of ERABSetupResponseIEField values.
type ERABSetupResponseIEContainer []ERABSetupResponseIEField

// ERABSetupResponseIEField is ProtocolIE-Field {{E-RABSetupResponseIEs}} of TS 36.413: an information element field.
type ERABSetupResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABSetupResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEField) WithoutReplay() ERABSetupResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABSetupResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupResponseIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABSetupResponseIEValue

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

// ERABModifyResponseIEContainer is ProtocolIE-Container {{E-RABModifyResponseIEs}} of TS 36.413: a list of ERABModifyResponseIEField values.
type ERABModifyResponseIEContainer []ERABModifyResponseIEField

// ERABModifyResponseIEField is ProtocolIE-Field {{E-RABModifyResponseIEs}} of TS 36.413: an information element field.
type ERABModifyResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModifyResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEField) WithoutReplay() ERABModifyResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABModifyResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyResponseIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABModifyResponseIEValue

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

// ERABReleaseResponseIEContainer is ProtocolIE-Container {{E-RABReleaseResponseIEs}} of TS 36.413: a list of ERABReleaseResponseIEField values.
type ERABReleaseResponseIEContainer []ERABReleaseResponseIEField

// ERABReleaseResponseIEField is ProtocolIE-Field {{E-RABReleaseResponseIEs}} of TS 36.413: an information element field.
type ERABReleaseResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABReleaseResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEField) WithoutReplay() ERABReleaseResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABReleaseResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseResponseIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABReleaseResponseIEValue

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

// ERABReleaseIndicationIEContainer is ProtocolIE-Container {{E-RABReleaseIndicationIEs}} of TS 36.413: a list of ERABReleaseIndicationIEField values.
type ERABReleaseIndicationIEContainer []ERABReleaseIndicationIEField

// ERABReleaseIndicationIEField is ProtocolIE-Field {{E-RABReleaseIndicationIEs}} of TS 36.413: an information element field.
type ERABReleaseIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABReleaseIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEField) WithoutReplay() ERABReleaseIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ERABReleaseIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseIndicationIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ERABReleaseIndicationIEValue

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

// UEContextReleaseCompleteIEContainer is ProtocolIE-Container {{UEContextReleaseComplete-IEs}} of TS 36.413: a list of UEContextReleaseCompleteIEField values.
type UEContextReleaseCompleteIEContainer []UEContextReleaseCompleteIEField

// UEContextReleaseCompleteIEField is ProtocolIE-Field {{UEContextReleaseComplete-IEs}} of TS 36.413: an information element field.
type UEContextReleaseCompleteIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextReleaseCompleteIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEField) WithoutReplay() UEContextReleaseCompleteIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextReleaseCompleteIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextReleaseCompleteIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *UEContextReleaseCompleteIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCompleteIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UEContextReleaseCompleteIEValue

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

// UEContextSuspendRequestIEContainer is ProtocolIE-Container {{UEContextSuspendRequestIEs}} of TS 36.413: a list of UEContextSuspendRequestIEField values.
type UEContextSuspendRequestIEContainer []UEContextSuspendRequestIEField

// UEContextSuspendRequestIEField is ProtocolIE-Field {{UEContextSuspendRequestIEs}} of TS 36.413: an information element field.
type UEContextSuspendRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextSuspendRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEField) WithoutReplay() UEContextSuspendRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextSuspendRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextSuspendRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *UEContextSuspendRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendRequestIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UEContextSuspendRequestIEValue

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

// SecondaryRATDataUsageReportIEContainer is ProtocolIE-Container {{SecondaryRATDataUsageReportIEs}} of TS 36.413: a list of SecondaryRATDataUsageReportIEField values.
type SecondaryRATDataUsageReportIEContainer []SecondaryRATDataUsageReportIEField

// SecondaryRATDataUsageReportIEField is ProtocolIE-Field {{SecondaryRATDataUsageReportIEs}} of TS 36.413: an information element field.
type SecondaryRATDataUsageReportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SecondaryRATDataUsageReportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEField) WithoutReplay() SecondaryRATDataUsageReportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecondaryRATDataUsageReportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecondaryRATDataUsageReportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *SecondaryRATDataUsageReportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReportIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero SecondaryRATDataUsageReportIEValue

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

// ERABModificationIndicationUserLocationInformationIEBinding binds UserLocationInformation to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) s44.ERABModificationIndicationIEValue

	get func(*s44.ERABModificationIndicationIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (s44.ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s44.ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Get(field *s44.ERABModificationIndicationIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UserLocationInformationValueCodec is the concrete ValueCodec[UserLocationInformation].
type UserLocationInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s44.UserLocationInformation,

		error)
	encode func(s44.UserLocationInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s44.UserLocationInformation, aper.DecodeState,

	) (s44.UserLocationInformation, aper.Snapshot,

	)
	compare func(s44.UserLocationInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UserLocationInformationValueCodec) New(value s44.UserLocationInformation,

) (UserLocationInformationAPERValue, error) {
	if c.encode == nil {
		return UserLocationInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UserLocationInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UserLocationInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UserLocationInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UserLocationInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UserLocationInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UserLocationInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UserLocationInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UserLocationInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UserLocationInformationValueCodec) EncodeAPER(value UserLocationInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UserLocationInformationValueCodec) encodeBudgetValue(value s44.UserLocationInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UserLocationInformationValueCodec) encodeChanged(value s44.UserLocationInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseMMEUES1APIDIEBinding) Get(field *ERABModifyResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseENBUES1APIDIEBinding binds ENBUES1APID to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseENBUES1APIDIEBinding) Get(field *ERABModifyResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseERABModifyListBearerModResIEBinding binds ERABModifyListBearerModRes to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseERABModifyListBearerModResIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABModifyListBearerModResValueCodec
	inject func(s16.ERABModifyListBearerModRes,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s16.ERABModifyListBearerModRes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseERABModifyListBearerModResIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseERABModifyListBearerModResIEBinding) Codec() s16.ERABModifyListBearerModResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseERABModifyListBearerModResIEBinding) New(value s16.ERABModifyListBearerModRes,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABModifyListBearerModResValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseERABModifyListBearerModResIEBinding) Get(field *ERABModifyResponseIEField) (*s16.ERABModifyListBearerModRes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseERABListIEBinding binds ERABList to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseERABListIEBinding) New(value s16.ERABList,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseERABListIEBinding) Get(field *ERABModifyResponseIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseCriticalityDiagnosticsIEBinding) Get(field *ERABModifyResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) Get(field *ERABModifyResponseIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) ERABModifyResponseIEValue

	get func(*ERABModifyResponseIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Get(field *ERABModifyResponseIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABReleaseIndicationIEValue

	get func(*ERABReleaseIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationMMEUES1APIDIEBinding) Get(field *ERABReleaseIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationENBUES1APIDIEBinding binds ENBUES1APID to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABReleaseIndicationIEValue

	get func(*ERABReleaseIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationENBUES1APIDIEBinding) Get(field *ERABReleaseIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationERABListIEBinding binds ERABList to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABReleaseIndicationIEValue

	get func(*ERABReleaseIndicationIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationERABListIEBinding) New(value s16.ERABList,

) (ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationERABListIEBinding) Get(field *ERABReleaseIndicationIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationUserLocationInformationIEBinding binds UserLocationInformation to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) ERABReleaseIndicationIEValue

	get func(*ERABReleaseIndicationIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Get(field *ERABReleaseIndicationIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) ERABReleaseIndicationIEValue

	get func(*ERABReleaseIndicationIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) Get(field *ERABReleaseIndicationIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseMMEUES1APIDIEBinding) Get(field *ERABReleaseResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseENBUES1APIDIEBinding binds ENBUES1APID to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseENBUES1APIDIEBinding) Get(field *ERABReleaseResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseERABReleaseListBearerRelCompIEBinding binds ERABReleaseListBearerRelComp to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseERABReleaseListBearerRelCompIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABReleaseListBearerRelCompValueCodec
	inject func(s16.ERABReleaseListBearerRelComp,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s16.ERABReleaseListBearerRelComp,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) Codec() s16.ERABReleaseListBearerRelCompValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) New(value s16.ERABReleaseListBearerRelComp,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) Get(field *ERABReleaseResponseIEField) (*s16.ERABReleaseListBearerRelComp,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseERABListIEBinding binds ERABList to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseERABListIEBinding) New(value s16.ERABList,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseERABListIEBinding) Get(field *ERABReleaseResponseIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseCriticalityDiagnosticsIEBinding) Get(field *ERABReleaseResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Get(field *ERABReleaseResponseIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) ERABReleaseResponseIEValue

	get func(*ERABReleaseResponseIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) Get(field *ERABReleaseResponseIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseMMEUES1APIDIEBinding) Get(field *ERABSetupResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseENBUES1APIDIEBinding binds ENBUES1APID to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseENBUES1APIDIEBinding) Get(field *ERABSetupResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseERABSetupListBearerSUResIEBinding binds ERABSetupListBearerSURes to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseERABSetupListBearerSUResIEBinding struct {
	info   s00.FieldInfo
	codec  s17.ERABSetupListBearerSUResValueCodec
	inject func(s17.ERABSetupListBearerSURes,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s17.ERABSetupListBearerSURes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseERABSetupListBearerSUResIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseERABSetupListBearerSUResIEBinding) Codec() s17.ERABSetupListBearerSUResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseERABSetupListBearerSUResIEBinding) New(value s17.ERABSetupListBearerSURes,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeERABSetupListBearerSUResValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseERABSetupListBearerSUResIEBinding) Get(field *ERABSetupResponseIEField) (*s17.ERABSetupListBearerSURes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseERABListIEBinding binds ERABList to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseERABListIEBinding) New(value s16.ERABList,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseERABListIEBinding) Get(field *ERABSetupResponseIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseCriticalityDiagnosticsIEBinding) Get(field *ERABSetupResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) ERABSetupResponseIEValue

	get func(*ERABSetupResponseIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Get(field *ERABSetupResponseIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportMMEUES1APIDIEBinding binds MMEUES1APID to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportMMEUES1APIDIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportENBUES1APIDIEBinding binds ENBUES1APID to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportENBUES1APIDIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportHandoverFlagIEBinding binds HandoverFlag to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportHandoverFlagIEBinding struct {
	info   s00.FieldInfo
	codec  s00.HandoverFlagValueCodec
	inject func(s00.HandoverFlag,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s00.HandoverFlag,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportHandoverFlagIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportHandoverFlagIEBinding) Codec() s00.HandoverFlagValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportHandoverFlagIEBinding) New(value s00.HandoverFlag,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeHandoverFlagValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportHandoverFlagIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s00.HandoverFlag,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportUserLocationInformationIEBinding binds UserLocationInformation to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding binds TimeSinceSecondaryNodeRelease to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeSinceSecondaryNodeReleaseValueCodec
	inject func(s00.TimeSinceSecondaryNodeRelease,

	) SecondaryRATDataUsageReportIEValue

	get func(*SecondaryRATDataUsageReportIEValue,

	) (*s00.TimeSinceSecondaryNodeRelease,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) Codec() s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) New(value s00.TimeSinceSecondaryNodeRelease,

) (SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) Get(field *SecondaryRATDataUsageReportIEField) (*s00.TimeSinceSecondaryNodeRelease,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteMMEUES1APIDIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteENBUES1APIDIEBinding binds ENBUES1APID to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteENBUES1APIDIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteUserLocationInformationIEBinding binds UserLocationInformation to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding binds InformationOnRecommendedCellsAndENBsForPaging to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec
	inject func(s33.InformationOnRecommendedCellsAndENBsForPaging,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s33.InformationOnRecommendedCellsAndENBsForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) Codec() s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) New(value s33.InformationOnRecommendedCellsAndENBsForPaging,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s33.InformationOnRecommendedCellsAndENBsForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding binds CellIdentifierAndCELevelForCECapableUEs to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CellIdentifierAndCELevelForCECapableUEsValueCodec
	inject func(s17.CellIdentifierAndCELevelForCECapableUEs,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s17.CellIdentifierAndCELevelForCECapableUEs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) Codec() s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) New(value s17.CellIdentifierAndCELevelForCECapableUEs,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s17.CellIdentifierAndCELevelForCECapableUEs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding binds TimeSinceSecondaryNodeRelease to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeSinceSecondaryNodeReleaseValueCodec
	inject func(s00.TimeSinceSecondaryNodeRelease,

	) UEContextReleaseCompleteIEValue

	get func(*UEContextReleaseCompleteIEValue,

	) (*s00.TimeSinceSecondaryNodeRelease,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) Codec() s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) New(value s00.TimeSinceSecondaryNodeRelease,

) (UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) Get(field *UEContextReleaseCompleteIEField) (*s00.TimeSinceSecondaryNodeRelease,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestMMEUES1APIDIEBinding) Get(field *UEContextSuspendRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestENBUES1APIDIEBinding binds ENBUES1APID to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestENBUES1APIDIEBinding) Get(field *UEContextSuspendRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding binds InformationOnRecommendedCellsAndENBsForPaging to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec
	inject func(s33.InformationOnRecommendedCellsAndENBsForPaging,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s33.InformationOnRecommendedCellsAndENBsForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) Codec() s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) New(value s33.InformationOnRecommendedCellsAndENBsForPaging,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) Get(field *UEContextSuspendRequestIEField) (*s33.InformationOnRecommendedCellsAndENBsForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding binds CellIdentifierAndCELevelForCECapableUEs to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CellIdentifierAndCELevelForCECapableUEsValueCodec
	inject func(s17.CellIdentifierAndCELevelForCECapableUEs,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s17.CellIdentifierAndCELevelForCECapableUEs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) Codec() s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) New(value s17.CellIdentifierAndCELevelForCECapableUEs,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) Get(field *UEContextSuspendRequestIEField) (*s17.CellIdentifierAndCELevelForCECapableUEs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) Get(field *UEContextSuspendRequestIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestUserLocationInformationIEBinding binds UserLocationInformation to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  UserLocationInformationValueCodec
	inject func(s44.UserLocationInformation,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s44.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Codec() UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) New(value s44.UserLocationInformation,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Get(field *UEContextSuspendRequestIEField) (*s44.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding binds TimeSinceSecondaryNodeRelease to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeSinceSecondaryNodeReleaseValueCodec
	inject func(s00.TimeSinceSecondaryNodeRelease,

	) UEContextSuspendRequestIEValue

	get func(*UEContextSuspendRequestIEValue,

	) (*s00.TimeSinceSecondaryNodeRelease,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) Codec() s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) New(value s00.TimeSinceSecondaryNodeRelease,

) (UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) Get(field *UEContextSuspendRequestIEField) (*s00.TimeSinceSecondaryNodeRelease,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UserLocationInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UserLocationInformation-ExtIEs}} codec of TS 36.413.
func UserLocationInformationExtIEsValueExtensionTableCodec(table s00.UserLocationInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s21.UserLocationInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeUserLocationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s21.UserLocationInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.UserLocationInformationExtIEsExtContainerValueCodec {
		sealed := s21.UserLocationInformationExtIEsExtContainerValueCodec{}
		*s21.BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UserLocationInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UserLocationInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UserLocationInformationExtIEsExtField
					if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s21.BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s21.UserLocationInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s21.UserLocationInformationExtIEsExtContainer, options aper.DecodeState) (s21.UserLocationInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s21.UserLocationInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s44.BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UserLocationInformationAPERValue is the concrete APERValue[UserLocationInformation].
type UserLocationInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s44.UserLocationInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UserLocationInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationAPERValue) WithoutReplay() UserLocationInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABModifyResponseIEValueERABIEContainerList].
type ERABModifyResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponseIEValueERABIEContainerList, error)
	encode  func(ERABModifyResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponseIEValueERABIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModifyResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseIEValueERABIEContainerListValueCodec) New(value ERABModifyResponseIEValueERABIEContainerList) (ERABModifyResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModifyResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModifyResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModifyResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABModifyResponseIEs}} of TS 36.413: a list of information element fields.
type ERABModifyResponseIEValueERABIEContainerList []ERABModifyResponseIEValueProtocolIESingleContainer

// ERABReleaseIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseIndicationIEValueERABIEContainerList].
type ERABReleaseIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueERABIEContainerList, error)
	encode  func(ERABReleaseIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndicationIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABReleaseIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationIEValueERABIEContainerListValueCodec) New(value ERABReleaseIndicationIEValueERABIEContainerList) (ERABReleaseIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABReleaseIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ERABReleaseIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABReleaseIndicationIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseIndicationIEValueERABIEContainerList []ERABReleaseIndicationIEValueProtocolIESingleContainer

// ERABReleaseResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseResponseIEValueERABIEContainerList].
type ERABReleaseResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueERABIEContainerList, error)
	encode  func(ERABReleaseResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponseIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseIEValueERABIEContainerListValueCodec) New(value ERABReleaseResponseIEValueERABIEContainerList) (ERABReleaseResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABReleaseResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseIEValueERABIEContainerListValueCodec) encodeChanged(value ERABReleaseResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABReleaseResponseIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseResponseIEValueERABIEContainerList []ERABReleaseResponseIEValueProtocolIESingleContainer

// ERABSetupResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABSetupResponseIEValueERABIEContainerList].
type ERABSetupResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponseIEValueERABIEContainerList, error)
	encode  func(ERABSetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponseIEValueERABIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseIEValueERABIEContainerListValueCodec) New(value ERABSetupResponseIEValueERABIEContainerList) (ERABSetupResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABSetupResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABSetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseIEValueERABIEContainerListValueCodec) encodeChanged(value ERABSetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABSetupResponseIEs}} of TS 36.413: a list of information element fields.
type ERABSetupResponseIEValueERABIEContainerList []ERABSetupResponseIEValueProtocolIESingleContainer

// SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportIEValueERABIEContainerList].
type SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueERABIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) New(value SecondaryRATDataUsageReportIEValueERABIEContainerList) (SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportIEValueERABIEContainerList is E-RAB-IE-ContainerList {{SecondaryRATDataUsageReportIEs}} of TS 36.413: a list of information element fields.
type SecondaryRATDataUsageReportIEValueERABIEContainerList []SecondaryRATDataUsageReportIEValueProtocolIESingleContainer

// UEContextReleaseCompleteIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCompleteIEValueERABIEContainerList].
type UEContextReleaseCompleteIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueERABIEContainerList, error)
	encode  func(UEContextReleaseCompleteIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCompleteIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) New(value UEContextReleaseCompleteIEValueERABIEContainerList) (UEContextReleaseCompleteIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCompleteIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCompleteIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextReleaseCompleteIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextReleaseComplete-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCompleteIEValueERABIEContainerList []UEContextReleaseCompleteIEValueProtocolIESingleContainer

// UEContextSuspendRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextSuspendRequestIEValueERABIEContainerList].
type UEContextSuspendRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueERABIEContainerList, error)
	encode  func(UEContextSuspendRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestIEValueERABIEContainerListValueCodec) New(value UEContextSuspendRequestIEValueERABIEContainerList) (UEContextSuspendRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextSuspendRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextSuspendRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextSuspendRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextSuspendRequestIEValueERABIEContainerList []UEContextSuspendRequestIEValueProtocolIESingleContainer

// ERABModifyResponseIEFieldValueCodec is the concrete ValueCodec[ERABModifyResponseIEField].
type ERABModifyResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponseIEField, error)
	encode  func(ERABModifyResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponseIEField, aper.DecodeState) (ERABModifyResponseIEField, aper.Snapshot)
	compare func(ERABModifyResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseIEFieldValueCodec) New(value ERABModifyResponseIEField) (ERABModifyResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseIEFieldValueCodec) EncodeAPER(value ERABModifyResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseIEFieldValueCodec) encodeBudgetValue(value ERABModifyResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseIEFieldValueCodec) encodeChanged(value ERABModifyResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationIEFieldValueCodec is the concrete ValueCodec[ERABReleaseIndicationIEField].
type ERABReleaseIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndicationIEField, error)
	encode  func(ERABReleaseIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndicationIEField, aper.DecodeState) (ERABReleaseIndicationIEField, aper.Snapshot)
	compare func(ERABReleaseIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationIEFieldValueCodec) New(value ERABReleaseIndicationIEField) (ERABReleaseIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationIEFieldValueCodec) EncodeAPER(value ERABReleaseIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationIEFieldValueCodec) encodeBudgetValue(value ERABReleaseIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationIEFieldValueCodec) encodeChanged(value ERABReleaseIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseIEFieldValueCodec is the concrete ValueCodec[ERABReleaseResponseIEField].
type ERABReleaseResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponseIEField, error)
	encode  func(ERABReleaseResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponseIEField, aper.DecodeState) (ERABReleaseResponseIEField, aper.Snapshot)
	compare func(ERABReleaseResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseIEFieldValueCodec) New(value ERABReleaseResponseIEField) (ERABReleaseResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseIEFieldValueCodec) EncodeAPER(value ERABReleaseResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseIEFieldValueCodec) encodeBudgetValue(value ERABReleaseResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseIEFieldValueCodec) encodeChanged(value ERABReleaseResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseIEFieldValueCodec is the concrete ValueCodec[ERABSetupResponseIEField].
type ERABSetupResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponseIEField, error)
	encode  func(ERABSetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponseIEField, aper.DecodeState) (ERABSetupResponseIEField, aper.Snapshot)
	compare func(ERABSetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseIEFieldValueCodec) New(value ERABSetupResponseIEField) (ERABSetupResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseIEFieldValueCodec) EncodeAPER(value ERABSetupResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseIEFieldValueCodec) encodeBudgetValue(value ERABSetupResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseIEFieldValueCodec) encodeChanged(value ERABSetupResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportIEFieldValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportIEField].
type SecondaryRATDataUsageReportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEField, error)
	encode  func(SecondaryRATDataUsageReportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportIEField, aper.DecodeState) (SecondaryRATDataUsageReportIEField, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportIEFieldValueCodec) New(value SecondaryRATDataUsageReportIEField) (SecondaryRATDataUsageReportIEFieldAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportIEFieldValueCodec) EncodeAPER(value SecondaryRATDataUsageReportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportIEFieldValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportIEFieldValueCodec) encodeChanged(value SecondaryRATDataUsageReportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteIEFieldValueCodec is the concrete ValueCodec[UEContextReleaseCompleteIEField].
type UEContextReleaseCompleteIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEField, error)
	encode  func(UEContextReleaseCompleteIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCompleteIEField, aper.DecodeState) (UEContextReleaseCompleteIEField, aper.Snapshot)
	compare func(UEContextReleaseCompleteIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteIEFieldValueCodec) New(value UEContextReleaseCompleteIEField) (UEContextReleaseCompleteIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteIEFieldValueCodec) EncodeAPER(value UEContextReleaseCompleteIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteIEFieldValueCodec) encodeBudgetValue(value UEContextReleaseCompleteIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteIEFieldValueCodec) encodeChanged(value UEContextReleaseCompleteIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestIEFieldValueCodec is the concrete ValueCodec[UEContextSuspendRequestIEField].
type UEContextSuspendRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequestIEField, error)
	encode  func(UEContextSuspendRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequestIEField, aper.DecodeState) (UEContextSuspendRequestIEField, aper.Snapshot)
	compare func(UEContextSuspendRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestIEFieldValueCodec) New(value UEContextSuspendRequestIEField) (UEContextSuspendRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestIEFieldValueCodec) EncodeAPER(value UEContextSuspendRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestIEFieldValueCodec) encodeBudgetValue(value UEContextSuspendRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestIEFieldValueCodec) encodeChanged(value UEContextSuspendRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseIEContainerValueCodec is the concrete ValueCodec[ERABModifyResponseIEContainer].
type ERABModifyResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponseIEContainer, error)
	encode  func(ERABModifyResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponseIEContainer, aper.DecodeState) (ERABModifyResponseIEContainer, aper.Snapshot)
	compare func(ERABModifyResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseIEContainerValueCodec) New(value ERABModifyResponseIEContainer) (ERABModifyResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseIEContainerValueCodec) EncodeAPER(value ERABModifyResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseIEContainerValueCodec) encodeBudgetValue(value ERABModifyResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseIEContainerValueCodec) encodeChanged(value ERABModifyResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationIEContainerValueCodec is the concrete ValueCodec[ERABReleaseIndicationIEContainer].
type ERABReleaseIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndicationIEContainer, error)
	encode  func(ERABReleaseIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndicationIEContainer, aper.DecodeState) (ERABReleaseIndicationIEContainer, aper.Snapshot)
	compare func(ERABReleaseIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationIEContainerValueCodec) New(value ERABReleaseIndicationIEContainer) (ERABReleaseIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationIEContainerValueCodec) EncodeAPER(value ERABReleaseIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationIEContainerValueCodec) encodeBudgetValue(value ERABReleaseIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationIEContainerValueCodec) encodeChanged(value ERABReleaseIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseIEContainerValueCodec is the concrete ValueCodec[ERABReleaseResponseIEContainer].
type ERABReleaseResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponseIEContainer, error)
	encode  func(ERABReleaseResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponseIEContainer, aper.DecodeState) (ERABReleaseResponseIEContainer, aper.Snapshot)
	compare func(ERABReleaseResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseIEContainerValueCodec) New(value ERABReleaseResponseIEContainer) (ERABReleaseResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseIEContainerValueCodec) EncodeAPER(value ERABReleaseResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseIEContainerValueCodec) encodeBudgetValue(value ERABReleaseResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseIEContainerValueCodec) encodeChanged(value ERABReleaseResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseIEContainerValueCodec is the concrete ValueCodec[ERABSetupResponseIEContainer].
type ERABSetupResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponseIEContainer, error)
	encode  func(ERABSetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponseIEContainer, aper.DecodeState) (ERABSetupResponseIEContainer, aper.Snapshot)
	compare func(ERABSetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseIEContainerValueCodec) New(value ERABSetupResponseIEContainer) (ERABSetupResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseIEContainerValueCodec) EncodeAPER(value ERABSetupResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseIEContainerValueCodec) encodeBudgetValue(value ERABSetupResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseIEContainerValueCodec) encodeChanged(value ERABSetupResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportIEContainerValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportIEContainer].
type SecondaryRATDataUsageReportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEContainer, error)
	encode  func(SecondaryRATDataUsageReportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportIEContainer, aper.DecodeState) (SecondaryRATDataUsageReportIEContainer, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportIEContainerValueCodec) New(value SecondaryRATDataUsageReportIEContainer) (SecondaryRATDataUsageReportIEContainerAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportIEContainerValueCodec) EncodeAPER(value SecondaryRATDataUsageReportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportIEContainerValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportIEContainerValueCodec) encodeChanged(value SecondaryRATDataUsageReportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteIEContainerValueCodec is the concrete ValueCodec[UEContextReleaseCompleteIEContainer].
type UEContextReleaseCompleteIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEContainer, error)
	encode  func(UEContextReleaseCompleteIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCompleteIEContainer, aper.DecodeState) (UEContextReleaseCompleteIEContainer, aper.Snapshot)
	compare func(UEContextReleaseCompleteIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteIEContainerValueCodec) New(value UEContextReleaseCompleteIEContainer) (UEContextReleaseCompleteIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteIEContainerValueCodec) EncodeAPER(value UEContextReleaseCompleteIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteIEContainerValueCodec) encodeBudgetValue(value UEContextReleaseCompleteIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteIEContainerValueCodec) encodeChanged(value UEContextReleaseCompleteIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestIEContainerValueCodec is the concrete ValueCodec[UEContextSuspendRequestIEContainer].
type UEContextSuspendRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequestIEContainer, error)
	encode  func(UEContextSuspendRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequestIEContainer, aper.DecodeState) (UEContextSuspendRequestIEContainer, aper.Snapshot)
	compare func(UEContextSuspendRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestIEContainerValueCodec) New(value UEContextSuspendRequestIEContainer) (UEContextSuspendRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestIEContainerValueCodec) EncodeAPER(value UEContextSuspendRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestIEContainerValueCodec) encodeBudgetValue(value UEContextSuspendRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestIEContainerValueCodec) encodeChanged(value UEContextSuspendRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABModifyResponseIEValueProtocolErrorIEContainerList].
type ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModifyResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModifyResponseIEValueProtocolErrorIEContainerList) (ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModifyResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModifyResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABModifyResponseIEs}} of TS 36.413: a list of information element fields.
type ERABModifyResponseIEValueProtocolErrorIEContainerList []ERABModifyResponseIEValueProtocolIESingleContainer

// ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseIndicationIEValueProtocolErrorIEContainerList].
type ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ERABReleaseIndicationIEValueProtocolErrorIEContainerList) (ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABReleaseIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABReleaseIndicationIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseIndicationIEValueProtocolErrorIEContainerList []ERABReleaseIndicationIEValueProtocolIESingleContainer

// ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseResponseIEValueProtocolErrorIEContainerList].
type ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) New(value ERABReleaseResponseIEValueProtocolErrorIEContainerList) (ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABReleaseResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABReleaseResponseIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseResponseIEValueProtocolErrorIEContainerList []ERABReleaseResponseIEValueProtocolIESingleContainer

// ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABSetupResponseIEValueProtocolErrorIEContainerList].
type ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABSetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) New(value ERABSetupResponseIEValueProtocolErrorIEContainerList) (ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABSetupResponseIEs}} of TS 36.413: a list of information element fields.
type ERABSetupResponseIEValueProtocolErrorIEContainerList []ERABSetupResponseIEValueProtocolIESingleContainer

// SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList].
type SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) New(value SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{SecondaryRATDataUsageReportIEs}} of TS 36.413: a list of information element fields.
type SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList []SecondaryRATDataUsageReportIEValueProtocolIESingleContainer

// UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCompleteIEValueProtocolErrorIEContainerList].
type UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextReleaseCompleteIEValueProtocolErrorIEContainerList) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextReleaseComplete-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCompleteIEValueProtocolErrorIEContainerList []UEContextReleaseCompleteIEValueProtocolIESingleContainer

// UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextSuspendRequestIEValueProtocolErrorIEContainerList].
type UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextSuspendRequestIEValueProtocolErrorIEContainerList) (UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextSuspendRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextSuspendRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextSuspendRequestIEValueProtocolErrorIEContainerList []UEContextSuspendRequestIEValueProtocolIESingleContainer

// ERABModifyResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABModifyResponseIEValueProtocolIEContainerList].
type ERABModifyResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponseIEValueProtocolIEContainerList, error)
	encode  func(ERABModifyResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModifyResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseIEValueProtocolIEContainerListValueCodec) New(value ERABModifyResponseIEValueProtocolIEContainerList) (ERABModifyResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModifyResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModifyResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModifyResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABModifyResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABModifyResponseIEValueProtocolIEContainerList []ERABModifyResponseIEValueProtocolIESingleContainer

// ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseIndicationIEValueProtocolIEContainerList].
type ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolIEContainerList, error)
	encode  func(ERABReleaseIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABReleaseIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) New(value ERABReleaseIndicationIEValueProtocolIEContainerList) (ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABReleaseIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABReleaseIndicationIEValueProtocolIEContainerList []ERABReleaseIndicationIEValueProtocolIESingleContainer

// ERABReleaseResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseResponseIEValueProtocolIEContainerList].
type ERABReleaseResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueProtocolIEContainerList, error)
	encode  func(ERABReleaseResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) New(value ERABReleaseResponseIEValueProtocolIEContainerList) (ERABReleaseResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABReleaseResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABReleaseResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABReleaseResponseIEValueProtocolIEContainerList []ERABReleaseResponseIEValueProtocolIESingleContainer

// ERABSetupResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABSetupResponseIEValueProtocolIEContainerList].
type ERABSetupResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponseIEValueProtocolIEContainerList, error)
	encode  func(ERABSetupResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseIEValueProtocolIEContainerListValueCodec) New(value ERABSetupResponseIEValueProtocolIEContainerList) (ERABSetupResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABSetupResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABSetupResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABSetupResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABSetupResponseIEValueProtocolIEContainerList []ERABSetupResponseIEValueProtocolIESingleContainer

// SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportIEValueProtocolIEContainerList].
type SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) New(value SecondaryRATDataUsageReportIEValueProtocolIEContainerList) (SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {SecondaryRATDataUsageReportIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type SecondaryRATDataUsageReportIEValueProtocolIEContainerList []SecondaryRATDataUsageReportIEValueProtocolIESingleContainer

// UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCompleteIEValueProtocolIEContainerList].
type UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolIEContainerList, error)
	encode  func(UEContextReleaseCompleteIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) New(value UEContextReleaseCompleteIEValueProtocolIEContainerList) (UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCompleteIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextReleaseCompleteIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseComplete-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextReleaseCompleteIEValueProtocolIEContainerList []UEContextReleaseCompleteIEValueProtocolIESingleContainer

// UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextSuspendRequestIEValueProtocolIEContainerList].
type UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolIEContainerList, error)
	encode  func(UEContextSuspendRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) New(value UEContextSuspendRequestIEValueProtocolIEContainerList) (UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextSuspendRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextSuspendRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextSuspendRequestIEValueProtocolIEContainerList []UEContextSuspendRequestIEValueProtocolIESingleContainer

// ERABModifyResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABModifyResponseIEValueERABIEContainerList].
type ERABModifyResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModifyResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABModifyResponseIEs}} of TS 36.413: a single information element field.
type ERABModifyResponseIEValueProtocolIESingleContainer = ERABModifyResponseIEField

// ERABReleaseIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABReleaseIndicationIEValueERABIEContainerList].
type ERABReleaseIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ERABReleaseIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABReleaseIndicationIEs}} of TS 36.413: a single information element field.
type ERABReleaseIndicationIEValueProtocolIESingleContainer = ERABReleaseIndicationIEField

// ERABReleaseResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABReleaseResponseIEValueERABIEContainerList].
type ERABReleaseResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEValueERABIEContainerListAPERValue) WithoutReplay() ERABReleaseResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABReleaseResponseIEs}} of TS 36.413: a single information element field.
type ERABReleaseResponseIEValueProtocolIESingleContainer = ERABReleaseResponseIEField

// ERABSetupResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABSetupResponseIEValueERABIEContainerList].
type ERABSetupResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEValueERABIEContainerListAPERValue) WithoutReplay() ERABSetupResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABSetupResponseIEs}} of TS 36.413: a single information element field.
type ERABSetupResponseIEValueProtocolIESingleContainer = ERABSetupResponseIEField

// SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue is the concrete APERValue[SecondaryRATDataUsageReportIEValueERABIEContainerList].
type SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{SecondaryRATDataUsageReportIEs}} of TS 36.413: a single information element field.
type SecondaryRATDataUsageReportIEValueProtocolIESingleContainer = SecondaryRATDataUsageReportIEField

// UEContextReleaseCompleteIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCompleteIEValueERABIEContainerList].
type UEContextReleaseCompleteIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCompleteIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextReleaseCompleteIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextReleaseComplete-IEs}} of TS 36.413: a single information element field.
type UEContextReleaseCompleteIEValueProtocolIESingleContainer = UEContextReleaseCompleteIEField

// UEContextSuspendRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextSuspendRequestIEValueERABIEContainerList].
type UEContextSuspendRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextSuspendRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextSuspendRequestIEs}} of TS 36.413: a single information element field.
type UEContextSuspendRequestIEValueProtocolIESingleContainer = UEContextSuspendRequestIEField

// ERABModifyResponseIEFieldAPERValue is the concrete APERValue[ERABModifyResponseIEField].
type ERABModifyResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEFieldAPERValue) WithoutReplay() ERABModifyResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationIEFieldAPERValue is the concrete APERValue[ERABReleaseIndicationIEField].
type ERABReleaseIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEFieldAPERValue) WithoutReplay() ERABReleaseIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseIEFieldAPERValue is the concrete APERValue[ERABReleaseResponseIEField].
type ERABReleaseResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEFieldAPERValue) WithoutReplay() ERABReleaseResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseIEFieldAPERValue is the concrete APERValue[ERABSetupResponseIEField].
type ERABSetupResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEFieldAPERValue) WithoutReplay() ERABSetupResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportIEFieldAPERValue is the concrete APERValue[SecondaryRATDataUsageReportIEField].
type SecondaryRATDataUsageReportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEFieldAPERValue) WithoutReplay() SecondaryRATDataUsageReportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteIEFieldAPERValue is the concrete APERValue[UEContextReleaseCompleteIEField].
type UEContextReleaseCompleteIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCompleteIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEFieldAPERValue) WithoutReplay() UEContextReleaseCompleteIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestIEFieldAPERValue is the concrete APERValue[UEContextSuspendRequestIEField].
type UEContextSuspendRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEFieldAPERValue) WithoutReplay() UEContextSuspendRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseIEContainerAPERValue is the concrete APERValue[ERABModifyResponseIEContainer].
type ERABModifyResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEContainerAPERValue) WithoutReplay() ERABModifyResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationIEContainerAPERValue is the concrete APERValue[ERABReleaseIndicationIEContainer].
type ERABReleaseIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEContainerAPERValue) WithoutReplay() ERABReleaseIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseIEContainerAPERValue is the concrete APERValue[ERABReleaseResponseIEContainer].
type ERABReleaseResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEContainerAPERValue) WithoutReplay() ERABReleaseResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseIEContainerAPERValue is the concrete APERValue[ERABSetupResponseIEContainer].
type ERABSetupResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEContainerAPERValue) WithoutReplay() ERABSetupResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportIEContainerAPERValue is the concrete APERValue[SecondaryRATDataUsageReportIEContainer].
type SecondaryRATDataUsageReportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEContainerAPERValue) WithoutReplay() SecondaryRATDataUsageReportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteIEContainerAPERValue is the concrete APERValue[UEContextReleaseCompleteIEContainer].
type UEContextReleaseCompleteIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCompleteIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEContainerAPERValue) WithoutReplay() UEContextReleaseCompleteIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestIEContainerAPERValue is the concrete APERValue[UEContextSuspendRequestIEContainer].
type UEContextSuspendRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEContainerAPERValue) WithoutReplay() UEContextSuspendRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABModifyResponseIEValueProtocolErrorIEContainerList].
type ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABReleaseIndicationIEValueProtocolErrorIEContainerList].
type ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABReleaseResponseIEValueProtocolErrorIEContainerList].
type ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABSetupResponseIEValueProtocolErrorIEContainerList].
type ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList].
type SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCompleteIEValueProtocolErrorIEContainerList].
type UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCompleteIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextSuspendRequestIEValueProtocolErrorIEContainerList].
type UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABModifyResponseIEValueProtocolIEContainerList].
type ERABModifyResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModifyResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABReleaseIndicationIEValueProtocolIEContainerList].
type ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABReleaseResponseIEValueProtocolIEContainerList].
type ERABReleaseResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABReleaseResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABSetupResponseIEValueProtocolIEContainerList].
type ERABSetupResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABSetupResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[SecondaryRATDataUsageReportIEValueProtocolIEContainerList].
type SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCompleteIEValueProtocolIEContainerList].
type UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCompleteIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextSuspendRequestIEValueProtocolIEContainerList].
type UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABModifyResponseIEValue(v *ERABModifyResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(31):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyListBearerModRes == nil)
				if v.rowERABModifyListBearerModRes != nil {
					s24.BridgeCaptureS1APERABModifyListBearerModRes(v.rowERABModifyListBearerModRes, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(32):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToModifyList == nil)
				if v.rowERABFailedToModifyList != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABFailedToModifyList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyResponseIEValue) captureSemantics(s aper.SemanticCapture) ERABModifyResponseIEValue {
	BridgeCaptureS1APERABModifyResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModifyResponseIEValue(v *ERABModifyResponseIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(31):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyListBearerModRes == nil)
				if v.rowERABModifyListBearerModRes != nil {
					s24.BridgeCompareS1APERABModifyListBearerModRes(v.rowERABModifyListBearerModRes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(32):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToModifyList == nil)
				if v.rowERABFailedToModifyList != nil {
					s24.BridgeCompareS1APERABList(v.rowERABFailedToModifyList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModifyResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABReleaseIndicationIEValue(v *ERABReleaseIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(110):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleasedList == nil)
				if v.rowERABReleasedList != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABReleasedList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseIndicationIEValue) captureSemantics(s aper.SemanticCapture) ERABReleaseIndicationIEValue {
	BridgeCaptureS1APERABReleaseIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABReleaseIndicationIEValue(v *ERABReleaseIndicationIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(110):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleasedList == nil)
				if v.rowERABReleasedList != nil {
					s24.BridgeCompareS1APERABList(v.rowERABReleasedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABReleaseIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABReleaseResponseIEValue(v *ERABReleaseResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(69):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleaseListBearerRelComp == nil)
				if v.rowERABReleaseListBearerRelComp != nil {
					s25.BridgeCaptureS1APERABReleaseListBearerRelComp(v.rowERABReleaseListBearerRelComp, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(34):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToReleaseList == nil)
				if v.rowERABFailedToReleaseList != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABFailedToReleaseList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseResponseIEValue) captureSemantics(s aper.SemanticCapture) ERABReleaseResponseIEValue {
	BridgeCaptureS1APERABReleaseResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABReleaseResponseIEValue(v *ERABReleaseResponseIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(69):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleaseListBearerRelComp == nil)
				if v.rowERABReleaseListBearerRelComp != nil {
					s25.BridgeCompareS1APERABReleaseListBearerRelComp(v.rowERABReleaseListBearerRelComp, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(34):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToReleaseList == nil)
				if v.rowERABFailedToReleaseList != nil {
					s24.BridgeCompareS1APERABList(v.rowERABFailedToReleaseList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABReleaseResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABSetupResponseIEValue(v *ERABSetupResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(28):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupListBearerSURes == nil)
				if v.rowERABSetupListBearerSURes != nil {
					s25.BridgeCaptureS1APERABSetupListBearerSURes(v.rowERABSetupListBearerSURes, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(29):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListBearerSURes == nil)
				if v.rowERABFailedToSetupListBearerSURes != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABFailedToSetupListBearerSURes, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupResponseIEValue) captureSemantics(s aper.SemanticCapture) ERABSetupResponseIEValue {
	BridgeCaptureS1APERABSetupResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABSetupResponseIEValue(v *ERABSetupResponseIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(28):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupListBearerSURes == nil)
				if v.rowERABSetupListBearerSURes != nil {
					s25.BridgeCompareS1APERABSetupListBearerSURes(v.rowERABSetupListBearerSURes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(29):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListBearerSURes == nil)
				if v.rowERABFailedToSetupListBearerSURes != nil {
					s24.BridgeCompareS1APERABList(v.rowERABFailedToSetupListBearerSURes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABSetupResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSecondaryRATDataUsageReportIEValue(v *SecondaryRATDataUsageReportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(266):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverFlag == nil)
				if v.rowHandoverFlag != nil {
					s00.BridgeCaptureS1APHandoverFlag(v.rowHandoverFlag, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SecondaryRATDataUsageReportIEValue) captureSemantics(s aper.SemanticCapture) SecondaryRATDataUsageReportIEValue {
	BridgeCaptureS1APSecondaryRATDataUsageReportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APSecondaryRATDataUsageReportIEValue(v *SecondaryRATDataUsageReportIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(266):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverFlag == nil)
				if v.rowHandoverFlag != nil {
					s02.BridgeCompareS1APHandoverFlag(v.rowHandoverFlag, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s07.BridgeCompareS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SecondaryRATDataUsageReportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSecondaryRATDataUsageReportIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextReleaseCompleteIEValue(v *UEContextReleaseCompleteIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(213):
			{
				f := s.Begin()
				s.Bool(v.rowInformationOnRecommendedCellsAndENBsForPaging == nil)
				if v.rowInformationOnRecommendedCellsAndENBsForPaging != nil {
					s33.BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(v.rowInformationOnRecommendedCellsAndENBsForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(212):
			{
				f := s.Begin()
				s.Bool(v.rowCellIdentifierAndCELevelForCECapableUEs == nil)
				if v.rowCellIdentifierAndCELevelForCECapableUEs != nil {
					s17.BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(v.rowCellIdentifierAndCELevelForCECapableUEs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCompleteIEValue) captureSemantics(s aper.SemanticCapture) UEContextReleaseCompleteIEValue {
	BridgeCaptureS1APUEContextReleaseCompleteIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextReleaseCompleteIEValue(v *UEContextReleaseCompleteIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(213):
			{
				f := s.Begin()
				s.Bool(v.rowInformationOnRecommendedCellsAndENBsForPaging == nil)
				if v.rowInformationOnRecommendedCellsAndENBsForPaging != nil {
					s33.BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(v.rowInformationOnRecommendedCellsAndENBsForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(212):
			{
				f := s.Begin()
				s.Bool(v.rowCellIdentifierAndCELevelForCECapableUEs == nil)
				if v.rowCellIdentifierAndCELevelForCECapableUEs != nil {
					s17.BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(v.rowCellIdentifierAndCELevelForCECapableUEs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s07.BridgeCompareS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCompleteIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextReleaseCompleteIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextSuspendRequestIEValue(v *UEContextSuspendRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(213):
			{
				f := s.Begin()
				s.Bool(v.rowInformationOnRecommendedCellsAndENBsForPaging == nil)
				if v.rowInformationOnRecommendedCellsAndENBsForPaging != nil {
					s33.BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(v.rowInformationOnRecommendedCellsAndENBsForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(212):
			{
				f := s.Begin()
				s.Bool(v.rowCellIdentifierAndCELevelForCECapableUEs == nil)
				if v.rowCellIdentifierAndCELevelForCECapableUEs != nil {
					s17.BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(v.rowCellIdentifierAndCELevelForCECapableUEs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextSuspendRequestIEValue) captureSemantics(s aper.SemanticCapture) UEContextSuspendRequestIEValue {
	BridgeCaptureS1APUEContextSuspendRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextSuspendRequestIEValue(v *UEContextSuspendRequestIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(213):
			{
				f := s.Begin()
				s.Bool(v.rowInformationOnRecommendedCellsAndENBsForPaging == nil)
				if v.rowInformationOnRecommendedCellsAndENBsForPaging != nil {
					s33.BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(v.rowInformationOnRecommendedCellsAndENBsForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(212):
			{
				f := s.Begin()
				s.Bool(v.rowCellIdentifierAndCELevelForCECapableUEs == nil)
				if v.rowCellIdentifierAndCELevelForCECapableUEs != nil {
					s17.BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(v.rowCellIdentifierAndCELevelForCECapableUEs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					s44.BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(297):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSinceSecondaryNodeRelease == nil)
				if v.rowTimeSinceSecondaryNodeRelease != nil {
					s07.BridgeCompareS1APTimeSinceSecondaryNodeRelease(v.rowTimeSinceSecondaryNodeRelease, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextSuspendRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextSuspendRequestIEValue(&v, &s)
	return s
}

type ERABModifyResponseIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABModifyListBearerModRes      *s16.ERABModifyListBearerModRes
	rowERABFailedToModifyList          *s16.ERABList
	rowCriticalityDiagnostics          *s22.CriticalityDiagnostics
	rowSecondaryRATDataUsageReportList *s28.SecondaryRATDataUsageReportList
	rowUserLocationInformation         *s44.UserLocationInformation
}

func (v ERABModifyResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(31):
		return v.rowERABModifyListBearerModRes != nil
	case s00.ProtocolIEID(32):
		return v.rowERABFailedToModifyList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABModifyResponseIEValue and reports whether the opaque alternative is selected.
func (v *ERABModifyResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModifyResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs"}}
}
func (ERABModifyResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(31):
		return aper.UnknownSelector
	case s00.ProtocolIEID(32):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABModifyListBearerModRes returns the selected ERABModifyListBearerModRes value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsERABModifyListBearerModRes() (*s16.ERABModifyListBearerModRes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(31) || v.rowERABModifyListBearerModRes == nil {
		return nil, false
	}
	return v.rowERABModifyListBearerModRes, true
}

// AsERABFailedToModifyList returns the selected ERABFailedToModifyList value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsERABFailedToModifyList() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(32) || v.rowERABFailedToModifyList == nil {
		return nil, false
	}
	return v.rowERABFailedToModifyList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of ERABModifyResponseIEValue and reports whether that alternative is active.
func (v *ERABModifyResponseIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}
func (v ERABModifyResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModifyResponseIEValue, error) {
	out := ERABModifyResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(31):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABModifyListBearerModResFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABModifyListBearerModRes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABModifyListBearerModRes = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(32):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToModifyList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToModifyList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
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
func (v ERABModifyResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABModifyResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(31):
		if v.rowERABModifyListBearerModRes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-E-RABModifyListBearerModRes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABModifyListBearerModResComplete{Value: *v.rowERABModifyListBearerModRes}
		candidate, err := s39.BridgeERABModifyListBearerModResCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(32):
		if v.rowERABFailedToModifyList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-E-RABFailedToModifyList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABFailedToModifyList}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyResponseIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModifyResponseIEValue:", v.id)
	}
}

type ERABReleaseIndicationIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABReleasedList                *s16.ERABList
	rowUserLocationInformation         *s44.UserLocationInformation
	rowSecondaryRATDataUsageReportList *s28.SecondaryRATDataUsageReportList
}

func (v ERABReleaseIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(110):
		return v.rowERABReleasedList != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABReleaseIndicationIEValue and reports whether the opaque alternative is selected.
func (v *ERABReleaseIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABReleaseIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs"}}
}
func (ERABReleaseIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(110):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABReleaseIndicationIEValue and reports whether that alternative is active.
func (v *ERABReleaseIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABReleaseIndicationIEValue and reports whether that alternative is active.
func (v *ERABReleaseIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABReleasedList returns the selected ERABReleasedList value of ERABReleaseIndicationIEValue and reports whether that alternative is active.
func (v *ERABReleaseIndicationIEValue) AsERABReleasedList() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(110) || v.rowERABReleasedList == nil {
		return nil, false
	}
	return v.rowERABReleasedList, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of ERABReleaseIndicationIEValue and reports whether that alternative is active.
func (v *ERABReleaseIndicationIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of ERABReleaseIndicationIEValue and reports whether that alternative is active.
func (v *ERABReleaseIndicationIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}
func (v ERABReleaseIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABReleaseIndicationIEValue, error) {
	out := ERABReleaseIndicationIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(110):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABReleasedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABReleasedList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
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
func (v ERABReleaseIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABReleaseIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseIndicationIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseIndicationIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(110):
		if v.rowERABReleasedList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseIndicationIEs.id-E-RABReleasedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABReleasedList}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseIndicationIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseIndicationIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABReleaseIndicationIEValue:", v.id)
	}
}

type ERABReleaseResponseIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABReleaseListBearerRelComp    *s16.ERABReleaseListBearerRelComp
	rowERABFailedToReleaseList         *s16.ERABList
	rowCriticalityDiagnostics          *s22.CriticalityDiagnostics
	rowUserLocationInformation         *s44.UserLocationInformation
	rowSecondaryRATDataUsageReportList *s28.SecondaryRATDataUsageReportList
}

func (v ERABReleaseResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(69):
		return v.rowERABReleaseListBearerRelComp != nil
	case s00.ProtocolIEID(34):
		return v.rowERABFailedToReleaseList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABReleaseResponseIEValue and reports whether the opaque alternative is selected.
func (v *ERABReleaseResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABReleaseResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs"}}
}
func (ERABReleaseResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(69):
		return aper.UnknownSelector
	case s00.ProtocolIEID(34):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABReleaseListBearerRelComp returns the selected ERABReleaseListBearerRelComp value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsERABReleaseListBearerRelComp() (*s16.ERABReleaseListBearerRelComp, bool) {
	if v == nil || v.id != s00.ProtocolIEID(69) || v.rowERABReleaseListBearerRelComp == nil {
		return nil, false
	}
	return v.rowERABReleaseListBearerRelComp, true
}

// AsERABFailedToReleaseList returns the selected ERABFailedToReleaseList value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsERABFailedToReleaseList() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(34) || v.rowERABFailedToReleaseList == nil {
		return nil, false
	}
	return v.rowERABFailedToReleaseList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of ERABReleaseResponseIEValue and reports whether that alternative is active.
func (v *ERABReleaseResponseIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}
func (v ERABReleaseResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABReleaseResponseIEValue, error) {
	out := ERABReleaseResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(69):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABReleaseListBearerRelCompFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABReleaseListBearerRelComp:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABReleaseListBearerRelComp = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(34):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToReleaseList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToReleaseList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
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
func (v ERABReleaseResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABReleaseResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(69):
		if v.rowERABReleaseListBearerRelComp == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-E-RABReleaseListBearerRelComp:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABReleaseListBearerRelCompComplete{Value: *v.rowERABReleaseListBearerRelComp}
		candidate, err := s39.BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(34):
		if v.rowERABFailedToReleaseList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-E-RABFailedToReleaseList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABFailedToReleaseList}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseResponseIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABReleaseResponseIEValue:", v.id)
	}
}

type ERABSetupResponseIEValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowMMEUES1APID                      *s00.MMEUES1APID
	rowENBUES1APID                      *s00.ENBUES1APID
	rowERABSetupListBearerSURes         *s17.ERABSetupListBearerSURes
	rowERABFailedToSetupListBearerSURes *s16.ERABList
	rowCriticalityDiagnostics           *s22.CriticalityDiagnostics
	rowUserLocationInformation          *s44.UserLocationInformation
}

func (v ERABSetupResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(28):
		return v.rowERABSetupListBearerSURes != nil
	case s00.ProtocolIEID(29):
		return v.rowERABFailedToSetupListBearerSURes != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABSetupResponseIEValue and reports whether the opaque alternative is selected.
func (v *ERABSetupResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABSetupResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs"}}
}
func (ERABSetupResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(28):
		return aper.UnknownSelector
	case s00.ProtocolIEID(29):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABSetupListBearerSURes returns the selected ERABSetupListBearerSURes value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsERABSetupListBearerSURes() (*s17.ERABSetupListBearerSURes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(28) || v.rowERABSetupListBearerSURes == nil {
		return nil, false
	}
	return v.rowERABSetupListBearerSURes, true
}

// AsERABFailedToSetupListBearerSURes returns the selected ERABFailedToSetupListBearerSURes value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsERABFailedToSetupListBearerSURes() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(29) || v.rowERABFailedToSetupListBearerSURes == nil {
		return nil, false
	}
	return v.rowERABFailedToSetupListBearerSURes, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of ERABSetupResponseIEValue and reports whether that alternative is active.
func (v *ERABSetupResponseIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}
func (v ERABSetupResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABSetupResponseIEValue, error) {
	out := ERABSetupResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(28):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABSetupListBearerSUResFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABSetupListBearerSURes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABSetupListBearerSURes = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(29):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToSetupListBearerSURes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToSetupListBearerSURes = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
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
func (v ERABSetupResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABSetupResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(28):
		if v.rowERABSetupListBearerSURes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-E-RABSetupListBearerSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABSetupListBearerSUResComplete{Value: *v.rowERABSetupListBearerSURes}
		candidate, err := s39.BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(29):
		if v.rowERABFailedToSetupListBearerSURes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-E-RABFailedToSetupListBearerSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABFailedToSetupListBearerSURes}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupResponseIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABSetupResponseIEValue:", v.id)
	}
}

type SecondaryRATDataUsageReportIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowSecondaryRATDataUsageReportList *s28.SecondaryRATDataUsageReportList
	rowHandoverFlag                    *s00.HandoverFlag
	rowUserLocationInformation         *s44.UserLocationInformation
	rowTimeSinceSecondaryNodeRelease   *s00.TimeSinceSecondaryNodeRelease
}

func (v SecondaryRATDataUsageReportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	case s00.ProtocolIEID(266):
		return v.rowHandoverFlag != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	case s00.ProtocolIEID(297):
		return v.rowTimeSinceSecondaryNodeRelease != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SecondaryRATDataUsageReportIEValue and reports whether the opaque alternative is selected.
func (v *SecondaryRATDataUsageReportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SecondaryRATDataUsageReportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs"}}
}
func (SecondaryRATDataUsageReportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(266):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
		return aper.UnknownSelector
	case s00.ProtocolIEID(297):
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
	case s00.ProtocolIEID(265):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}

// AsHandoverFlag returns the selected HandoverFlag value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsHandoverFlag() (*s00.HandoverFlag, bool) {
	if v == nil || v.id != s00.ProtocolIEID(266) || v.rowHandoverFlag == nil {
		return nil, false
	}
	return v.rowHandoverFlag, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}

// AsTimeSinceSecondaryNodeRelease returns the selected TimeSinceSecondaryNodeRelease value of SecondaryRATDataUsageReportIEValue and reports whether that alternative is active.
func (v *SecondaryRATDataUsageReportIEValue) AsTimeSinceSecondaryNodeRelease() (*s00.TimeSinceSecondaryNodeRelease, bool) {
	if v == nil || v.id != s00.ProtocolIEID(297) || v.rowTimeSinceSecondaryNodeRelease == nil {
		return nil, false
	}
	return v.rowTimeSinceSecondaryNodeRelease, true
}
func (v SecondaryRATDataUsageReportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SecondaryRATDataUsageReportIEValue, error) {
	out := SecondaryRATDataUsageReportIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(266):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "HandoverFlag"})
		value := s00.HandoverFlag(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "HandoverFlag:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowHandoverFlag = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(297):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TimeSinceSecondaryNodeRelease, error) {
			var v struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TimeSinceSecondaryNodeRelease(val_value)
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
		out.rowTimeSinceSecondaryNodeRelease = &value
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
func (v SecondaryRATDataUsageReportIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v SecondaryRATDataUsageReportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(266):
		if v.rowHandoverFlag == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-HandoverFlag:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowHandoverFlag), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(297):
		if v.rowTimeSinceSecondaryNodeRelease == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportIEs.id-TimeSinceSecondaryNodeRelease:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TimeSinceSecondaryNodeRelease, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowTimeSinceSecondaryNodeRelease, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SecondaryRATDataUsageReportIEValue:", v.id)
	}
}

type UEContextReleaseCompleteIEValue struct {
	id                                               s00.ProtocolIEID
	received                                         aper.WireSpan
	replay                                           aper.Snapshot
	opaque                                           aper.OpaqueOpenType
	isOpaque                                         bool
	rowMMEUES1APID                                   *s00.MMEUES1APID
	rowENBUES1APID                                   *s00.ENBUES1APID
	rowCriticalityDiagnostics                        *s22.CriticalityDiagnostics
	rowUserLocationInformation                       *s44.UserLocationInformation
	rowInformationOnRecommendedCellsAndENBsForPaging *s33.InformationOnRecommendedCellsAndENBsForPaging
	rowCellIdentifierAndCELevelForCECapableUEs       *s17.CellIdentifierAndCELevelForCECapableUEs
	rowSecondaryRATDataUsageReportList               *s28.SecondaryRATDataUsageReportList
	rowTimeSinceSecondaryNodeRelease                 *s00.TimeSinceSecondaryNodeRelease
}

func (v UEContextReleaseCompleteIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	case s00.ProtocolIEID(213):
		return v.rowInformationOnRecommendedCellsAndENBsForPaging != nil
	case s00.ProtocolIEID(212):
		return v.rowCellIdentifierAndCELevelForCECapableUEs != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	case s00.ProtocolIEID(297):
		return v.rowTimeSinceSecondaryNodeRelease != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextReleaseCompleteIEValue and reports whether the opaque alternative is selected.
func (v *UEContextReleaseCompleteIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextReleaseCompleteIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs"}}
}
func (UEContextReleaseCompleteIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
		return aper.UnknownSelector
	case s00.ProtocolIEID(213):
		return aper.UnknownSelector
	case s00.ProtocolIEID(212):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(297):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}

// AsInformationOnRecommendedCellsAndENBsForPaging returns the selected InformationOnRecommendedCellsAndENBsForPaging value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsInformationOnRecommendedCellsAndENBsForPaging() (*s33.InformationOnRecommendedCellsAndENBsForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(213) || v.rowInformationOnRecommendedCellsAndENBsForPaging == nil {
		return nil, false
	}
	return v.rowInformationOnRecommendedCellsAndENBsForPaging, true
}

// AsCellIdentifierAndCELevelForCECapableUEs returns the selected CellIdentifierAndCELevelForCECapableUEs value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsCellIdentifierAndCELevelForCECapableUEs() (*s17.CellIdentifierAndCELevelForCECapableUEs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(212) || v.rowCellIdentifierAndCELevelForCECapableUEs == nil {
		return nil, false
	}
	return v.rowCellIdentifierAndCELevelForCECapableUEs, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}

// AsTimeSinceSecondaryNodeRelease returns the selected TimeSinceSecondaryNodeRelease value of UEContextReleaseCompleteIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCompleteIEValue) AsTimeSinceSecondaryNodeRelease() (*s00.TimeSinceSecondaryNodeRelease, bool) {
	if v == nil || v.id != s00.ProtocolIEID(297) || v.rowTimeSinceSecondaryNodeRelease == nil {
		return nil, false
	}
	return v.rowTimeSinceSecondaryNodeRelease, true
}
func (v UEContextReleaseCompleteIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextReleaseCompleteIEValue, error) {
	out := UEContextReleaseCompleteIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(213):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s33.InformationOnRecommendedCellsAndENBsForPaging
		child := scope
		if err := s33.BridgeInformationOnRecommendedCellsAndENBsForPagingMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "InformationOnRecommendedCellsAndENBsForPaging:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InformationOnRecommendedCellsAndENBsForPaging")
		if err != nil {
			return out, err
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldPerPadding(&value) = padding
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceived(&value) = true
		raw.RetainContents(s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedBytes(&value))
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowInformationOnRecommendedCellsAndENBsForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(212):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.CellIdentifierAndCELevelForCECapableUEs
		child := scope
		if err := s17.BridgeCellIdentifierAndCELevelForCECapableUEsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CellIdentifierAndCELevelForCECapableUEs:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CellIdentifierAndCELevelForCECapableUEs")
		if err != nil {
			return out, err
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldPerPadding(&value) = padding
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedBytes(&value))
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCellIdentifierAndCELevelForCECapableUEs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(297):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TimeSinceSecondaryNodeRelease, error) {
			var v struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TimeSinceSecondaryNodeRelease(val_value)
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
		out.rowTimeSinceSecondaryNodeRelease = &value
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
func (v UEContextReleaseCompleteIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextReleaseCompleteIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(213):
		if v.rowInformationOnRecommendedCellsAndENBsForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-InformationOnRecommendedCellsAndENBsForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s33.BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERBudget(v.rowInformationOnRecommendedCellsAndENBsForPaging, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(212):
		if v.rowCellIdentifierAndCELevelForCECapableUEs == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-CellIdentifierAndCELevelForCECapableUEs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeCellIdentifierAndCELevelForCECapableUEsMethodMarshalAPERBudget(v.rowCellIdentifierAndCELevelForCECapableUEs, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(297):
		if v.rowTimeSinceSecondaryNodeRelease == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseComplete-IEs.id-TimeSinceSecondaryNodeRelease:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TimeSinceSecondaryNodeRelease, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowTimeSinceSecondaryNodeRelease, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextReleaseCompleteIEValue:", v.id)
	}
}

type UEContextSuspendRequestIEValue struct {
	id                                               s00.ProtocolIEID
	received                                         aper.WireSpan
	replay                                           aper.Snapshot
	opaque                                           aper.OpaqueOpenType
	isOpaque                                         bool
	rowMMEUES1APID                                   *s00.MMEUES1APID
	rowENBUES1APID                                   *s00.ENBUES1APID
	rowInformationOnRecommendedCellsAndENBsForPaging *s33.InformationOnRecommendedCellsAndENBsForPaging
	rowCellIdentifierAndCELevelForCECapableUEs       *s17.CellIdentifierAndCELevelForCECapableUEs
	rowSecondaryRATDataUsageReportList               *s28.SecondaryRATDataUsageReportList
	rowUserLocationInformation                       *s44.UserLocationInformation
	rowTimeSinceSecondaryNodeRelease                 *s00.TimeSinceSecondaryNodeRelease
}

func (v UEContextSuspendRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(213):
		return v.rowInformationOnRecommendedCellsAndENBsForPaging != nil
	case s00.ProtocolIEID(212):
		return v.rowCellIdentifierAndCELevelForCECapableUEs != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	case s00.ProtocolIEID(297):
		return v.rowTimeSinceSecondaryNodeRelease != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextSuspendRequestIEValue and reports whether the opaque alternative is selected.
func (v *UEContextSuspendRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextSuspendRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs"}}
}
func (UEContextSuspendRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(213):
		return aper.UnknownSelector
	case s00.ProtocolIEID(212):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
		return aper.UnknownSelector
	case s00.ProtocolIEID(297):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsInformationOnRecommendedCellsAndENBsForPaging returns the selected InformationOnRecommendedCellsAndENBsForPaging value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsInformationOnRecommendedCellsAndENBsForPaging() (*s33.InformationOnRecommendedCellsAndENBsForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(213) || v.rowInformationOnRecommendedCellsAndENBsForPaging == nil {
		return nil, false
	}
	return v.rowInformationOnRecommendedCellsAndENBsForPaging, true
}

// AsCellIdentifierAndCELevelForCECapableUEs returns the selected CellIdentifierAndCELevelForCECapableUEs value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsCellIdentifierAndCELevelForCECapableUEs() (*s17.CellIdentifierAndCELevelForCECapableUEs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(212) || v.rowCellIdentifierAndCELevelForCECapableUEs == nil {
		return nil, false
	}
	return v.rowCellIdentifierAndCELevelForCECapableUEs, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsUserLocationInformation() (*s44.UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}

// AsTimeSinceSecondaryNodeRelease returns the selected TimeSinceSecondaryNodeRelease value of UEContextSuspendRequestIEValue and reports whether that alternative is active.
func (v *UEContextSuspendRequestIEValue) AsTimeSinceSecondaryNodeRelease() (*s00.TimeSinceSecondaryNodeRelease, bool) {
	if v == nil || v.id != s00.ProtocolIEID(297) || v.rowTimeSinceSecondaryNodeRelease == nil {
		return nil, false
	}
	return v.rowTimeSinceSecondaryNodeRelease, true
}
func (v UEContextSuspendRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextSuspendRequestIEValue, error) {
	out := UEContextSuspendRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(213):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s33.InformationOnRecommendedCellsAndENBsForPaging
		child := scope
		if err := s33.BridgeInformationOnRecommendedCellsAndENBsForPagingMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "InformationOnRecommendedCellsAndENBsForPaging:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InformationOnRecommendedCellsAndENBsForPaging")
		if err != nil {
			return out, err
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldPerPadding(&value) = padding
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceived(&value) = true
		raw.RetainContents(s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedBytes(&value))
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowInformationOnRecommendedCellsAndENBsForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(212):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.CellIdentifierAndCELevelForCECapableUEs
		child := scope
		if err := s17.BridgeCellIdentifierAndCELevelForCECapableUEsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CellIdentifierAndCELevelForCECapableUEs:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CellIdentifierAndCELevelForCECapableUEs")
		if err != nil {
			return out, err
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldPerPadding(&value) = padding
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedBytes(&value))
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCellIdentifierAndCELevelForCECapableUEs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s44.UserLocationInformation
		child := scope
		if err := s44.BridgeUserLocationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		*s44.BridgeUserLocationInformationFieldPerPadding(&value) = padding
		*s44.BridgeUserLocationInformationFieldReceived(&value) = true
		raw.RetainContents(s44.BridgeUserLocationInformationFieldReceivedBytes(&value))
		*s44.BridgeUserLocationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUserLocationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(297):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TimeSinceSecondaryNodeRelease, error) {
			var v struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TimeSinceSecondaryNodeRelease(val_value)
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
		out.rowTimeSinceSecondaryNodeRelease = &value
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
func (v UEContextSuspendRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextSuspendRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(213):
		if v.rowInformationOnRecommendedCellsAndENBsForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-InformationOnRecommendedCellsAndENBsForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s33.BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERBudget(v.rowInformationOnRecommendedCellsAndENBsForPaging, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(212):
		if v.rowCellIdentifierAndCELevelForCECapableUEs == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-CellIdentifierAndCELevelForCECapableUEs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeCellIdentifierAndCELevelForCECapableUEsMethodMarshalAPERBudget(v.rowCellIdentifierAndCELevelForCECapableUEs, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s44.BridgeUserLocationInformationMethodMarshalAPERBudget(v.rowUserLocationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(297):
		if v.rowTimeSinceSecondaryNodeRelease == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendRequestIEs.id-TimeSinceSecondaryNodeRelease:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TimeSinceSecondaryNodeRelease, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TimeSinceSecondaryNodeRelease
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowTimeSinceSecondaryNodeRelease, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextSuspendRequestIEValue:", v.id)
	}
}

type ERABModificationIndicationIETable struct{}

func ERABModificationIndicationIEs() ERABModificationIndicationIETable {
	return ERABModificationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ERABModificationIndicationIETable.
func (ERABModificationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModificationIndicationIETable.
func (ERABModificationIndicationIETable) Table() s00.ERABModificationIndicationIEValueIETable {
	return func() s00.ERABModificationIndicationIEValueIETable {
		sealed := s00.ERABModificationIndicationIEValueIETable{}
		*s00.BridgeERABModificationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) MMEUES1APID() s44.ERABModificationIndicationMMEUES1APIDIEBinding {
	return func() s44.ERABModificationIndicationMMEUES1APIDIEBinding {
		sealed := s44.ERABModificationIndicationMMEUES1APIDIEBinding{}
		*s44.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s44.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s44.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		}()
		*s44.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s44.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ENBUES1APID() s44.ERABModificationIndicationENBUES1APIDIEBinding {
	return func() s44.ERABModificationIndicationENBUES1APIDIEBinding {
		sealed := s44.ERABModificationIndicationENBUES1APIDIEBinding{}
		*s44.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s44.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s44.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s44.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s44.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoERABToBeModifiedListBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(199), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedListBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-E-RABToBeModifiedListBearerModInd"}}}
}

// ERABToBeModifiedListBearerModInd returns the typed binding for the ERABToBeModifiedListBearerModInd row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ERABToBeModifiedListBearerModInd() s44.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding {
	return func() s44.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding {
		sealed := s44.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding{}
		*s44.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInfo(&sealed) = t.infoERABToBeModifiedListBearerModInd()
		*s44.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldCodec(&sealed) = func() s17.ERABToBeModifiedListBearerModIndValueCodec {
			sealed := s17.ERABToBeModifiedListBearerModIndValueCodec{}
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldPath(&sealed) = "ERABToBeModifiedListBearerModInd"
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeModifiedListBearerModInd, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.ERABToBeModifiedListBearerModInd
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABToBeModifiedListBearerModInd")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(199), raw)
				if err != nil {
					var empty s17.ERABToBeModifiedListBearerModInd
					return empty, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
				}
				value, ok := decoded.AsERABToBeModifiedListBearerModInd()
				if !ok {
					var empty s17.ERABToBeModifiedListBearerModInd
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-E-RABToBeModifiedListBearerModInd: no selected value")
				}
				return *value, nil
			}
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeModifiedListBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
					*s44.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeModifiedListBearerModInd, options aper.DecodeState) (s17.ERABToBeModifiedListBearerModInd, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s25.BridgeCaptureS1APERABToBeModifiedListBearerModInd(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeModifiedListBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s25.BridgeCompareS1APERABToBeModifiedListBearerModInd(&v,
					&s,
				)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeModifiedListBearerModInd"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s44.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInject(&sealed) = func(value s17.ERABToBeModifiedListBearerModInd) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
				*s44.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s17.ERABToBeModifiedListBearerModInd, bool) {
			return value.AsERABToBeModifiedListBearerModInd()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoERABNotToBeModifiedListBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(201), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedListBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-E-RABNotToBeModifiedListBearerModInd"}}}
}

// ERABNotToBeModifiedListBearerModInd returns the typed binding for the ERABNotToBeModifiedListBearerModInd row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ERABNotToBeModifiedListBearerModInd() s44.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding {
	return func() s44.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding {
		sealed := s44.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding{}
		*s44.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInfo(&sealed) = t.infoERABNotToBeModifiedListBearerModInd()
		*s44.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldCodec(&sealed) = func() s16.ERABNotToBeModifiedListBearerModIndValueCodec {
			sealed := s16.ERABNotToBeModifiedListBearerModIndValueCodec{}
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedListBearerModInd"
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABNotToBeModifiedListBearerModInd, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s16.ERABNotToBeModifiedListBearerModInd
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABNotToBeModifiedListBearerModInd")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(201), raw)
				if err != nil {
					var empty s16.ERABNotToBeModifiedListBearerModInd
					return empty, runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
				}
				value, ok := decoded.AsERABNotToBeModifiedListBearerModInd()
				if !ok {
					var empty s16.ERABNotToBeModifiedListBearerModInd
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-E-RABNotToBeModifiedListBearerModInd: no selected value")
				}
				return *value, nil
			}
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldEncode(&sealed) = func(value s16.ERABNotToBeModifiedListBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
					*s44.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCapture(&sealed) = func(v s16.ERABNotToBeModifiedListBearerModInd, options aper.DecodeState) (s16.ERABNotToBeModifiedListBearerModInd, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s24.BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCompare(&sealed) = func(v s16.ERABNotToBeModifiedListBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s24.BridgeCompareS1APERABNotToBeModifiedListBearerModInd(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABNotToBeModifiedListBearerModInd"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s44.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInject(&sealed) = func(value s16.ERABNotToBeModifiedListBearerModInd) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
				*s44.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s16.ERABNotToBeModifiedListBearerModInd, bool) {
			return value.AsERABNotToBeModifiedListBearerModInd()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoCSGMembershipInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(226), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-CSGMembershipInfo"}}}
}

// CSGMembershipInfo returns the typed binding for the CSGMembershipInfo row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) CSGMembershipInfo() s44.ERABModificationIndicationCSGMembershipInfoIEBinding {
	return func() s44.ERABModificationIndicationCSGMembershipInfoIEBinding {
		sealed := s44.ERABModificationIndicationCSGMembershipInfoIEBinding{}
		*s44.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInfo(&sealed) = t.infoCSGMembershipInfo()
		*s44.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldCodec(&sealed) = func() s14.CSGMembershipInfoValueCodec {
			sealed := s14.CSGMembershipInfoValueCodec{}
			*s14.BridgeCSGMembershipInfoValueCodecFieldPath(&sealed) = "CSGMembershipInfo"
			*s14.BridgeCSGMembershipInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CSGMembershipInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s14.CSGMembershipInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGMembershipInfo")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(226), raw)
				if err != nil {
					var empty s14.CSGMembershipInfo
					return empty, runtime.WrapDecodePath(err, "CSGMembershipInfo")
				}
				value, ok := decoded.AsCSGMembershipInfo()
				if !ok {
					var empty s14.CSGMembershipInfo
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-CSGMembershipInfo: no selected value")
				}
				return *value, nil
			}
			*s14.BridgeCSGMembershipInfoValueCodecFieldEncode(&sealed) = func(value s14.CSGMembershipInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
					*s44.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s14.BridgeCSGMembershipInfoValueCodecFieldCapture(&sealed) = func(v s14.CSGMembershipInfo, options aper.DecodeState) (s14.CSGMembershipInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s14.BridgeCaptureS1APCSGMembershipInfo(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s14.BridgeCSGMembershipInfoValueCodecFieldCompare(&sealed) = func(v s14.CSGMembershipInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s14.BridgeCompareS1APCSGMembershipInfo(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s14.BridgeCSGMembershipInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s44.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInject(&sealed) = func(value s14.CSGMembershipInfo) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s44.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s14.CSGMembershipInfo, bool) {
			return value.AsCSGMembershipInfo()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-Tunnel-Information-for-BBF"}}}
}

// TunnelInformationForBBF returns the typed binding for the TunnelInformationForBBF row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) TunnelInformationForBBF() s44.ERABModificationIndicationTunnelInformationIEBinding {
	return func() s44.ERABModificationIndicationTunnelInformationIEBinding {
		sealed := s44.ERABModificationIndicationTunnelInformationIEBinding{}
		*s44.BridgeERABModificationIndicationTunnelInformationIEBindingFieldInfo(&sealed) = t.infoTunnelInformationForBBF()
		*s44.BridgeERABModificationIndicationTunnelInformationIEBindingFieldCodec(&sealed) = func() s35.TunnelInformationValueCodec {
			sealed := s35.TunnelInformationValueCodec{}
			*s35.BridgeTunnelInformationValueCodecFieldPath(&sealed) = "TunnelInformation"
			*s35.BridgeTunnelInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.TunnelInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s35.TunnelInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TunnelInformation")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(176), raw)
				if err != nil {
					var empty s35.TunnelInformation
					return empty, runtime.WrapDecodePath(err, "TunnelInformation")
				}
				value, ok := decoded.AsTunnelInformationForBBF()
				if !ok {
					var empty s35.TunnelInformation
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-Tunnel-Information-for-BBF: no selected value")
				}
				return *value, nil
			}
			*s35.BridgeTunnelInformationValueCodecFieldEncode(&sealed) = func(value s35.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
					*s44.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s35.BridgeTunnelInformationValueCodecFieldCapture(&sealed) = func(v s35.TunnelInformation, options aper.DecodeState) (s35.TunnelInformation, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s35.BridgeCaptureS1APTunnelInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s35.BridgeTunnelInformationValueCodecFieldCompare(&sealed) = func(v s35.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s35.BridgeCompareS1APTunnelInformation(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s35.BridgeTunnelInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s44.BridgeERABModificationIndicationTunnelInformationIEBindingFieldInject(&sealed) = func(value s35.TunnelInformation) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s44.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationTunnelInformationIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s35.TunnelInformation, bool) {
			return value.AsTunnelInformationForBBF()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) SecondaryRATDataUsageReportList() s44.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding {
	return func() s44.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding {
		sealed := s44.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding{}
		*s44.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s44.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s28.SecondaryRATDataUsageReportListValueCodec {
			sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s28.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s44.ERABModificationIndicationIEValue
				decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s28.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s28.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
					sealed := s44.ERABModificationIndicationIEValue{}
					*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s44.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s44.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s28.SecondaryRATDataUsageReportList) s44.ERABModificationIndicationIEValue {
			return func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s44.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s44.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s44.ERABModificationIndicationIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) UserLocationInformation() ERABModificationIndicationUserLocationInformationIEBinding {
	return ERABModificationIndicationUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s44.ERABModificationIndicationIEValue
			decoded, err := s44.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s44.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s44.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) s44.ERABModificationIndicationIEValue {
		return func() s44.ERABModificationIndicationIEValue {
			sealed := s44.ERABModificationIndicationIEValue{}
			*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
			*s44.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s44.ERABModificationIndicationIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s44.ERABModificationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(199):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeModifiedListBearerModInd requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(201):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABNotToBeModifiedListBearerModInd requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(226):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s44.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s44.ERABModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s44.ERABModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s44.ERABModificationIndicationIEField{Id: id, Criticality: criticality, Value: func() s44.ERABModificationIndicationIEValue {
			sealed := s44.ERABModificationIndicationIEValue{}
			*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = id
			*s44.BridgeERABModificationIndicationIEValueFieldOpaque(&sealed) = opaque
			*s44.BridgeERABModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyResponseIETable struct{}

func ERABModifyResponseIEs() ERABModifyResponseIETable { return ERABModifyResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABModifyResponseIETable.
func (ERABModifyResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModifyResponseIETable.
func (ERABModifyResponseIETable) Table() s00.ERABModifyResponseIEValueIETable {
	return func() s00.ERABModifyResponseIEValueIETable {
		sealed := s00.ERABModifyResponseIEValueIETable{}
		*s00.BridgeERABModifyResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) MMEUES1APID() ERABModifyResponseMMEUES1APIDIEBinding {
	return ERABModifyResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABModifyResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ENBUES1APID() ERABModifyResponseENBUES1APIDIEBinding {
	return ERABModifyResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABModifyResponseIETable) infoERABModifyListBearerModRes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(31), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyListBearerModRes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-E-RABModifyListBearerModRes"}}}
}

// ERABModifyListBearerModRes returns the typed binding for the ERABModifyListBearerModRes row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ERABModifyListBearerModRes() ERABModifyResponseERABModifyListBearerModResIEBinding {
	return ERABModifyResponseERABModifyListBearerModResIEBinding{info: t.infoERABModifyListBearerModRes(), codec: func() s16.ERABModifyListBearerModResValueCodec {
		sealed := s16.ERABModifyListBearerModResValueCodec{}
		*s16.BridgeERABModifyListBearerModResValueCodecFieldPath(&sealed) = "ERABModifyListBearerModRes"
		*s16.BridgeERABModifyListBearerModResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyListBearerModRes, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABModifyListBearerModRes
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABModifyListBearerModRes")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(31), raw)
			if err != nil {
				var empty s16.ERABModifyListBearerModRes
				return empty, runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
			}
			value, ok := decoded.AsERABModifyListBearerModRes()
			if !ok {
				var empty s16.ERABModifyListBearerModRes
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-E-RABModifyListBearerModRes: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABModifyListBearerModResValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyListBearerModRes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(31), rowERABModifyListBearerModRes: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABModifyListBearerModResValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyListBearerModRes, options aper.DecodeState) (s16.ERABModifyListBearerModRes, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABModifyListBearerModRes(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyListBearerModResValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyListBearerModRes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABModifyListBearerModRes(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyListBearerModResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyListBearerModRes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABModifyListBearerModRes) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(31), rowERABModifyListBearerModRes: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s16.ERABModifyListBearerModRes, bool) {
			return value.AsERABModifyListBearerModRes()
		}}
}
func (ERABModifyResponseIETable) infoERABFailedToModifyList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(32), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-E-RABFailedToModifyList"}}}
}

// ERABFailedToModifyList returns the typed binding for the ERABFailedToModifyList row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ERABFailedToModifyList() ERABModifyResponseERABListIEBinding {
	return ERABModifyResponseERABListIEBinding{info: t.infoERABFailedToModifyList(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(32), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABFailedToModifyList()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-E-RABFailedToModifyList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(32), rowERABFailedToModifyList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(32), rowERABFailedToModifyList: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s16.ERABList, bool) { return value.AsERABFailedToModifyList() }}
}
func (ERABModifyResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) CriticalityDiagnostics() ERABModifyResponseCriticalityDiagnosticsIEBinding {
	return ERABModifyResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ERABModifyResponseIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) SecondaryRATDataUsageReportList() ERABModifyResponseSecondaryRATDataUsageReportListIEBinding {
	return ERABModifyResponseSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) ERABModifyResponseIEValue {
			return ERABModifyResponseIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *ERABModifyResponseIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}
func (ERABModifyResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) UserLocationInformation() ERABModifyResponseUserLocationInformationIEBinding {
	return ERABModifyResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero ERABModifyResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) ERABModifyResponseIEValue {
		return ERABModifyResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *ERABModifyResponseIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABModifyResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(31):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABModifyListBearerModRes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(32):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToModifyList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyResponseIEField{Id: id, Criticality: criticality, Value: ERABModifyResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseIndicationIETable struct{}

func ERABReleaseIndicationIEs() ERABReleaseIndicationIETable { return ERABReleaseIndicationIETable{} }

// ID returns the ASN.1 object-set identity of ERABReleaseIndicationIETable.
func (ERABReleaseIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseIndicationIETable.
func (ERABReleaseIndicationIETable) Table() s00.ERABReleaseIndicationIEValueIETable {
	return func() s00.ERABReleaseIndicationIEValueIETable {
		sealed := s00.ERABReleaseIndicationIEValueIETable{}
		*s00.BridgeERABReleaseIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) MMEUES1APID() ERABReleaseIndicationMMEUES1APIDIEBinding {
	return ERABReleaseIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABReleaseIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABReleaseIndicationIEValue {
			return ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABReleaseIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABReleaseIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) ENBUES1APID() ERABReleaseIndicationENBUES1APIDIEBinding {
	return ERABReleaseIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABReleaseIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABReleaseIndicationIEValue {
			return ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABReleaseIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABReleaseIndicationIETable) infoERABReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(110), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-E-RABReleasedList"}}}
}

// ERABReleasedList returns the typed binding for the ERABReleasedList row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) ERABReleasedList() ERABReleaseIndicationERABListIEBinding {
	return ERABReleaseIndicationERABListIEBinding{info: t.infoERABReleasedList(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABReleaseIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(110), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABReleasedList()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-E-RABReleasedList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(110), rowERABReleasedList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABReleaseIndicationIEValue {
			return ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(110), rowERABReleasedList: &value}
		}, get: func(value *ERABReleaseIndicationIEValue) (*s16.ERABList, bool) { return value.AsERABReleasedList() }}
}
func (ERABReleaseIndicationIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) UserLocationInformation() ERABReleaseIndicationUserLocationInformationIEBinding {
	return ERABReleaseIndicationUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero ERABReleaseIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) ERABReleaseIndicationIEValue {
		return ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *ERABReleaseIndicationIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}
func (ERABReleaseIndicationIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) SecondaryRATDataUsageReportList() ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding {
	return ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
			var zero ERABReleaseIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) ERABReleaseIndicationIEValue {
			return ERABReleaseIndicationIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *ERABReleaseIndicationIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABReleaseIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(110):
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABReleaseIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABReleaseIndicationIEField{Id: id, Criticality: criticality, Value: ERABReleaseIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseResponseIETable struct{}

func ERABReleaseResponseIEs() ERABReleaseResponseIETable { return ERABReleaseResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABReleaseResponseIETable.
func (ERABReleaseResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseResponseIETable.
func (ERABReleaseResponseIETable) Table() s00.ERABReleaseResponseIEValueIETable {
	return func() s00.ERABReleaseResponseIEValueIETable {
		sealed := s00.ERABReleaseResponseIEValueIETable{}
		*s00.BridgeERABReleaseResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) MMEUES1APID() ERABReleaseResponseMMEUES1APIDIEBinding {
	return ERABReleaseResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABReleaseResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ENBUES1APID() ERABReleaseResponseENBUES1APIDIEBinding {
	return ERABReleaseResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABReleaseResponseIETable) infoERABReleaseListBearerRelComp() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(69), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseListBearerRelComp"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-E-RABReleaseListBearerRelComp"}}}
}

// ERABReleaseListBearerRelComp returns the typed binding for the ERABReleaseListBearerRelComp row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ERABReleaseListBearerRelComp() ERABReleaseResponseERABReleaseListBearerRelCompIEBinding {
	return ERABReleaseResponseERABReleaseListBearerRelCompIEBinding{info: t.infoERABReleaseListBearerRelComp(), codec: func() s16.ERABReleaseListBearerRelCompValueCodec {
		sealed := s16.ERABReleaseListBearerRelCompValueCodec{}
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldPath(&sealed) = "ERABReleaseListBearerRelComp"
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABReleaseListBearerRelComp, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABReleaseListBearerRelComp
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABReleaseListBearerRelComp")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(69), raw)
			if err != nil {
				var empty s16.ERABReleaseListBearerRelComp
				return empty, runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
			}
			value, ok := decoded.AsERABReleaseListBearerRelComp()
			if !ok {
				var empty s16.ERABReleaseListBearerRelComp
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-E-RABReleaseListBearerRelComp: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldEncode(&sealed) = func(value s16.ERABReleaseListBearerRelComp, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(69), rowERABReleaseListBearerRelComp: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldCapture(&sealed) = func(v s16.ERABReleaseListBearerRelComp, options aper.DecodeState) (s16.ERABReleaseListBearerRelComp, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APERABReleaseListBearerRelComp(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldCompare(&sealed) = func(v s16.ERABReleaseListBearerRelComp, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s25.BridgeCompareS1APERABReleaseListBearerRelComp(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABReleaseListBearerRelCompValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseListBearerRelComp"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABReleaseListBearerRelComp) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(69), rowERABReleaseListBearerRelComp: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s16.ERABReleaseListBearerRelComp, bool) {
			return value.AsERABReleaseListBearerRelComp()
		}}
}
func (ERABReleaseResponseIETable) infoERABFailedToReleaseList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(34), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-E-RABFailedToReleaseList"}}}
}

// ERABFailedToReleaseList returns the typed binding for the ERABFailedToReleaseList row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ERABFailedToReleaseList() ERABReleaseResponseERABListIEBinding {
	return ERABReleaseResponseERABListIEBinding{info: t.infoERABFailedToReleaseList(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(34), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABFailedToReleaseList()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-E-RABFailedToReleaseList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(34), rowERABFailedToReleaseList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(34), rowERABFailedToReleaseList: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s16.ERABList, bool) {
			return value.AsERABFailedToReleaseList()
		}}
}
func (ERABReleaseResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) CriticalityDiagnostics() ERABReleaseResponseCriticalityDiagnosticsIEBinding {
	return ERABReleaseResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ERABReleaseResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) UserLocationInformation() ERABReleaseResponseUserLocationInformationIEBinding {
	return ERABReleaseResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) ERABReleaseResponseIEValue {
		return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *ERABReleaseResponseIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}
func (ERABReleaseResponseIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) SecondaryRATDataUsageReportList() ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding {
	return ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
			var zero ERABReleaseResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseResponseIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) ERABReleaseResponseIEValue {
			return ERABReleaseResponseIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *ERABReleaseResponseIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABReleaseResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(69):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABReleaseListBearerRelComp requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(34):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToReleaseList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABReleaseResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABReleaseResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABReleaseResponseIEField{Id: id, Criticality: criticality, Value: ERABReleaseResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupResponseIETable struct{}

func ERABSetupResponseIEs() ERABSetupResponseIETable { return ERABSetupResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABSetupResponseIETable.
func (ERABSetupResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupResponseIETable.
func (ERABSetupResponseIETable) Table() s00.ERABSetupResponseIEValueIETable {
	return func() s00.ERABSetupResponseIEValueIETable {
		sealed := s00.ERABSetupResponseIEValueIETable{}
		*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) MMEUES1APID() ERABSetupResponseMMEUES1APIDIEBinding {
	return ERABSetupResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABSetupResponseIEValue {
			return ERABSetupResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABSetupResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABSetupResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ENBUES1APID() ERABSetupResponseENBUES1APIDIEBinding {
	return ERABSetupResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABSetupResponseIEValue {
			return ERABSetupResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABSetupResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABSetupResponseIETable) infoERABSetupListBearerSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(28), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupListBearerSURes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-E-RABSetupListBearerSURes"}}}
}

// ERABSetupListBearerSURes returns the typed binding for the ERABSetupListBearerSURes row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ERABSetupListBearerSURes() ERABSetupResponseERABSetupListBearerSUResIEBinding {
	return ERABSetupResponseERABSetupListBearerSUResIEBinding{info: t.infoERABSetupListBearerSURes(), codec: func() s17.ERABSetupListBearerSUResValueCodec {
		sealed := s17.ERABSetupListBearerSUResValueCodec{}
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldPath(&sealed) = "ERABSetupListBearerSURes"
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABSetupListBearerSURes, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.ERABSetupListBearerSURes
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABSetupListBearerSURes")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(28), raw)
			if err != nil {
				var empty s17.ERABSetupListBearerSURes
				return empty, runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
			}
			value, ok := decoded.AsERABSetupListBearerSURes()
			if !ok {
				var empty s17.ERABSetupListBearerSURes
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-E-RABSetupListBearerSURes: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldEncode(&sealed) = func(value s17.ERABSetupListBearerSURes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(28), rowERABSetupListBearerSURes: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldCapture(&sealed) = func(v s17.ERABSetupListBearerSURes, options aper.DecodeState) (s17.ERABSetupListBearerSURes, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APERABSetupListBearerSURes(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldCompare(&sealed) = func(v s17.ERABSetupListBearerSURes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APERABSetupListBearerSURes(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABSetupListBearerSUResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupListBearerSURes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.ERABSetupListBearerSURes) ERABSetupResponseIEValue {
			return ERABSetupResponseIEValue{id: s00.ProtocolIEID(28), rowERABSetupListBearerSURes: &value}
		}, get: func(value *ERABSetupResponseIEValue) (*s17.ERABSetupListBearerSURes, bool) {
			return value.AsERABSetupListBearerSURes()
		}}
}
func (ERABSetupResponseIETable) infoERABFailedToSetupListBearerSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(29), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-E-RABFailedToSetupListBearerSURes"}}}
}

// ERABFailedToSetupListBearerSURes returns the typed binding for the ERABFailedToSetupListBearerSURes row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ERABFailedToSetupListBearerSURes() ERABSetupResponseERABListIEBinding {
	return ERABSetupResponseERABListIEBinding{info: t.infoERABFailedToSetupListBearerSURes(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(29), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABFailedToSetupListBearerSURes()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-E-RABFailedToSetupListBearerSURes: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(29), rowERABFailedToSetupListBearerSURes: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABSetupResponseIEValue {
			return ERABSetupResponseIEValue{id: s00.ProtocolIEID(29), rowERABFailedToSetupListBearerSURes: &value}
		}, get: func(value *ERABSetupResponseIEValue) (*s16.ERABList, bool) {
			return value.AsERABFailedToSetupListBearerSURes()
		}}
}
func (ERABSetupResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) CriticalityDiagnostics() ERABSetupResponseCriticalityDiagnosticsIEBinding {
	return ERABSetupResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) ERABSetupResponseIEValue {
			return ERABSetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ERABSetupResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ERABSetupResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) UserLocationInformation() ERABSetupResponseUserLocationInformationIEBinding {
	return ERABSetupResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero ERABSetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) ERABSetupResponseIEValue {
		return ERABSetupResponseIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *ERABSetupResponseIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABSetupResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(28):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSetupListBearerSURes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(29):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToSetupListBearerSURes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupResponseIEField{Id: id, Criticality: criticality, Value: ERABSetupResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type SecondaryRATDataUsageReportIETable struct{}

func SecondaryRATDataUsageReportIEs() SecondaryRATDataUsageReportIETable {
	return SecondaryRATDataUsageReportIETable{}
}

// ID returns the ASN.1 object-set identity of SecondaryRATDataUsageReportIETable.
func (SecondaryRATDataUsageReportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecondaryRATDataUsageReportIETable.
func (SecondaryRATDataUsageReportIETable) Table() s00.SecondaryRATDataUsageReportIEValueIETable {
	return func() s00.SecondaryRATDataUsageReportIEValueIETable {
		sealed := s00.SecondaryRATDataUsageReportIEValueIETable{}
		*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) MMEUES1APID() SecondaryRATDataUsageReportMMEUES1APIDIEBinding {
	return SecondaryRATDataUsageReportMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) SecondaryRATDataUsageReportIEValue {
			return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (SecondaryRATDataUsageReportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) ENBUES1APID() SecondaryRATDataUsageReportENBUES1APIDIEBinding {
	return SecondaryRATDataUsageReportENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) SecondaryRATDataUsageReportIEValue {
			return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (SecondaryRATDataUsageReportIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) SecondaryRATDataUsageReportList() SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding {
	return SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) SecondaryRATDataUsageReportIEValue {
			return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}
func (SecondaryRATDataUsageReportIETable) infoHandoverFlag() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(266), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverFlag"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-HandoverFlag"}}}
}

// HandoverFlag returns the typed binding for the HandoverFlag row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) HandoverFlag() SecondaryRATDataUsageReportHandoverFlagIEBinding {
	return SecondaryRATDataUsageReportHandoverFlagIEBinding{info: t.infoHandoverFlag(), codec: func() s00.HandoverFlagValueCodec {
		sealed := s00.HandoverFlagValueCodec{}
		*s00.BridgeHandoverFlagValueCodecFieldPath(&sealed) = "HandoverFlag"
		*s00.BridgeHandoverFlagValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverFlag, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.HandoverFlag
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("HandoverFlag")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(266), raw)
			if err != nil {
				var empty s00.HandoverFlag
				return empty, runtime.WrapDecodePath(err, "HandoverFlag")
			}
			value, ok := decoded.AsHandoverFlag()
			if !ok {
				var empty s00.HandoverFlag
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-HandoverFlag: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeHandoverFlagValueCodecFieldEncode(&sealed) = func(value s00.HandoverFlag, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(266), rowHandoverFlag: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeHandoverFlagValueCodecFieldCapture(&sealed) = func(v s00.HandoverFlag, options aper.DecodeState) (s00.HandoverFlag, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHandoverFlag(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHandoverFlagValueCodecFieldCompare(&sealed) = func(v s00.HandoverFlag, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHandoverFlag(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeHandoverFlagValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverFlag"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.HandoverFlag) SecondaryRATDataUsageReportIEValue {
			return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(266), rowHandoverFlag: &value}
		}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s00.HandoverFlag, bool) {
			return value.AsHandoverFlag()
		}}
}
func (SecondaryRATDataUsageReportIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) UserLocationInformation() SecondaryRATDataUsageReportUserLocationInformationIEBinding {
	return SecondaryRATDataUsageReportUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) SecondaryRATDataUsageReportIEValue {
		return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}
func (SecondaryRATDataUsageReportIETable) infoTimeSinceSecondaryNodeRelease() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(297), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSinceSecondaryNodeRelease"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-TimeSinceSecondaryNodeRelease"}}}
}

// TimeSinceSecondaryNodeRelease returns the typed binding for the TimeSinceSecondaryNodeRelease row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) TimeSinceSecondaryNodeRelease() SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding {
	return SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding{info: t.infoTimeSinceSecondaryNodeRelease(), codec: func() s02.TimeSinceSecondaryNodeReleaseValueCodec {
		sealed := s02.TimeSinceSecondaryNodeReleaseValueCodec{}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(&sealed) = "TimeSinceSecondaryNodeRelease"
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeSinceSecondaryNodeRelease")
			var zero SecondaryRATDataUsageReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(297), raw)
			if err != nil {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, runtime.WrapDecodePath(err, "TimeSinceSecondaryNodeRelease")
			}
			value, ok := decoded.AsTimeSinceSecondaryNodeRelease()
			if !ok {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-TimeSinceSecondaryNodeRelease: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(297), rowTimeSinceSecondaryNodeRelease: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s07.BridgeCompareS1APTimeSinceSecondaryNodeRelease(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSinceSecondaryNodeRelease"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeSinceSecondaryNodeRelease) SecondaryRATDataUsageReportIEValue {
			return SecondaryRATDataUsageReportIEValue{id: s00.ProtocolIEID(297), rowTimeSinceSecondaryNodeRelease: &value}
		}, get: func(value *SecondaryRATDataUsageReportIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
			return value.AsTimeSinceSecondaryNodeRelease()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SecondaryRATDataUsageReportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(266):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverFlag requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(297):
		return SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeSinceSecondaryNodeRelease requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Opaque")
		}
		return SecondaryRATDataUsageReportIEField{Id: id, Criticality: criticality, Value: SecondaryRATDataUsageReportIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextReleaseCompleteIETable struct{}

func UEContextReleaseCompleteIEs() UEContextReleaseCompleteIETable {
	return UEContextReleaseCompleteIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextReleaseCompleteIETable.
func (UEContextReleaseCompleteIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextReleaseCompleteIETable.
func (UEContextReleaseCompleteIETable) Table() s00.UEContextReleaseCompleteIEValueIETable {
	return func() s00.UEContextReleaseCompleteIEValueIETable {
		sealed := s00.UEContextReleaseCompleteIEValueIETable{}
		*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) MMEUES1APID() UEContextReleaseCompleteMMEUES1APIDIEBinding {
	return UEContextReleaseCompleteMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextReleaseCompleteIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) ENBUES1APID() UEContextReleaseCompleteENBUES1APIDIEBinding {
	return UEContextReleaseCompleteENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UEContextReleaseCompleteIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) CriticalityDiagnostics() UEContextReleaseCompleteCriticalityDiagnosticsIEBinding {
	return UEContextReleaseCompleteCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (UEContextReleaseCompleteIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) UserLocationInformation() UEContextReleaseCompleteUserLocationInformationIEBinding {
	return UEContextReleaseCompleteUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: UserLocationInformationValueCodec{path: "UserLocationInformation",
		decode: func(data []byte, options aper.DecodeState) (s44.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s44.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s44.UserLocationInformation
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s44.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s44.UserLocationInformation, options aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v s44.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s44.UserLocationInformation) UEContextReleaseCompleteIEValue {
		return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(189), rowUserLocationInformation: &value}
	}, get: func(value *UEContextReleaseCompleteIEValue) (*s44.UserLocationInformation, bool) {
		return value.AsUserLocationInformation()
	}}
}
func (UEContextReleaseCompleteIETable) infoInformationOnRecommendedCellsAndENBsForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(213), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InformationOnRecommendedCellsAndENBsForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-InformationOnRecommendedCellsAndENBsForPaging"}}}
}

// InformationOnRecommendedCellsAndENBsForPaging returns the typed binding for the InformationOnRecommendedCellsAndENBsForPaging row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) InformationOnRecommendedCellsAndENBsForPaging() UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding {
	return UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding{info: t.infoInformationOnRecommendedCellsAndENBsForPaging(), codec: func() s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
		sealed := s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec{}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldPath(&sealed) = "InformationOnRecommendedCellsAndENBsForPaging"
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.InformationOnRecommendedCellsAndENBsForPaging, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s33.InformationOnRecommendedCellsAndENBsForPaging
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("InformationOnRecommendedCellsAndENBsForPaging")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(213), raw)
			if err != nil {
				var empty s33.InformationOnRecommendedCellsAndENBsForPaging
				return empty, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
			}
			value, ok := decoded.AsInformationOnRecommendedCellsAndENBsForPaging()
			if !ok {
				var empty s33.InformationOnRecommendedCellsAndENBsForPaging
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-InformationOnRecommendedCellsAndENBsForPaging: no selected value")
			}
			return *value, nil
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(&sealed) = func(value s33.InformationOnRecommendedCellsAndENBsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(213), rowInformationOnRecommendedCellsAndENBsForPaging: &value}).encodeFresh(fresh, budget)
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCapture(&sealed) = func(v s33.InformationOnRecommendedCellsAndENBsForPaging, options aper.DecodeState) (s33.InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s33.BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCompare(&sealed) = func(v s33.InformationOnRecommendedCellsAndENBsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(
				root, budget)
			f := s.Begin()
			s33.BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InformationOnRecommendedCellsAndENBsForPaging"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s33.InformationOnRecommendedCellsAndENBsForPaging) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(213), rowInformationOnRecommendedCellsAndENBsForPaging: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s33.InformationOnRecommendedCellsAndENBsForPaging, bool) {
			return value.AsInformationOnRecommendedCellsAndENBsForPaging()
		}}
}
func (UEContextReleaseCompleteIETable) infoCellIdentifierAndCELevelForCECapableUEs() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(212), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellIdentifierAndCELevelForCECapableUEs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-CellIdentifierAndCELevelForCECapableUEs"}}}
}

// CellIdentifierAndCELevelForCECapableUEs returns the typed binding for the CellIdentifierAndCELevelForCECapableUEs row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) CellIdentifierAndCELevelForCECapableUEs() UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding {
	return UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding{info: t.infoCellIdentifierAndCELevelForCECapableUEs(), codec: func() s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
		sealed := s17.CellIdentifierAndCELevelForCECapableUEsValueCodec{}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldPath(&sealed) = "CellIdentifierAndCELevelForCECapableUEs"
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellIdentifierAndCELevelForCECapableUEs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.CellIdentifierAndCELevelForCECapableUEs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CellIdentifierAndCELevelForCECapableUEs")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(212), raw)
			if err != nil {
				var empty s17.CellIdentifierAndCELevelForCECapableUEs
				return empty, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
			}
			value, ok := decoded.AsCellIdentifierAndCELevelForCECapableUEs()
			if !ok {
				var empty s17.CellIdentifierAndCELevelForCECapableUEs
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-CellIdentifierAndCELevelForCECapableUEs: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(&sealed) = func(value s17.CellIdentifierAndCELevelForCECapableUEs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(212), rowCellIdentifierAndCELevelForCECapableUEs: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCapture(&sealed) = func(v s17.CellIdentifierAndCELevelForCECapableUEs, options aper.DecodeState) (s17.CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCompare(&sealed) = func(v s17.CellIdentifierAndCELevelForCECapableUEs, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s17.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdentifierAndCELevelForCECapableUEs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.CellIdentifierAndCELevelForCECapableUEs) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(212), rowCellIdentifierAndCELevelForCECapableUEs: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s17.CellIdentifierAndCELevelForCECapableUEs, bool) {
			return value.AsCellIdentifierAndCELevelForCECapableUEs()
		}}
}
func (UEContextReleaseCompleteIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) SecondaryRATDataUsageReportList() UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding {
	return UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}
func (UEContextReleaseCompleteIETable) infoTimeSinceSecondaryNodeRelease() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(297), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSinceSecondaryNodeRelease"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-TimeSinceSecondaryNodeRelease"}}}
}

// TimeSinceSecondaryNodeRelease returns the typed binding for the TimeSinceSecondaryNodeRelease row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) TimeSinceSecondaryNodeRelease() UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding {
	return UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding{info: t.infoTimeSinceSecondaryNodeRelease(), codec: func() s02.TimeSinceSecondaryNodeReleaseValueCodec {
		sealed := s02.TimeSinceSecondaryNodeReleaseValueCodec{}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(&sealed) = "TimeSinceSecondaryNodeRelease"
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeSinceSecondaryNodeRelease")
			var zero UEContextReleaseCompleteIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(297), raw)
			if err != nil {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, runtime.WrapDecodePath(err, "TimeSinceSecondaryNodeRelease")
			}
			value, ok := decoded.AsTimeSinceSecondaryNodeRelease()
			if !ok {
				var empty s00.TimeSinceSecondaryNodeRelease
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-TimeSinceSecondaryNodeRelease: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(297), rowTimeSinceSecondaryNodeRelease: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s07.BridgeCompareS1APTimeSinceSecondaryNodeRelease(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSinceSecondaryNodeRelease"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeSinceSecondaryNodeRelease) UEContextReleaseCompleteIEValue {
			return UEContextReleaseCompleteIEValue{id: s00.ProtocolIEID(297), rowTimeSinceSecondaryNodeRelease: &value}
		}, get: func(value *UEContextReleaseCompleteIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
			return value.AsTimeSinceSecondaryNodeRelease()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextReleaseCompleteIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(213):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-InformationOnRecommendedCellsAndENBsForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(212):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellIdentifierAndCELevelForCECapableUEs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(297):
		return UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeSinceSecondaryNodeRelease requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextReleaseCompleteIEField{Id: id, Criticality: criticality, Value: UEContextReleaseCompleteIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CSGMembershipInfoCodec binds the complete APER value type.
func CSGMembershipInfoCodec() s14.CSGMembershipInfoValueCodec {
	return ERABModificationIndicationIEs().CSGMembershipInfo().Codec()
}

// CellIdentifierAndCELevelForCECapableUEsCodec binds the complete APER value type.
func CellIdentifierAndCELevelForCECapableUEsCodec() s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Codec()
}

// ERABModifyListBearerModResCodec binds the complete APER value type.
func ERABModifyListBearerModResCodec() s16.ERABModifyListBearerModResValueCodec {
	return ERABModifyResponseIEs().ERABModifyListBearerModRes().Codec()
}

// ERABNotToBeModifiedListBearerModIndCodec binds the complete APER value type.
func ERABNotToBeModifiedListBearerModIndCodec() s16.ERABNotToBeModifiedListBearerModIndValueCodec {
	return ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Codec()
}

// ERABReleaseListBearerRelCompCodec binds the complete APER value type.
func ERABReleaseListBearerRelCompCodec() s16.ERABReleaseListBearerRelCompValueCodec {
	return ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Codec()
}

// ERABSetupListBearerSUResCodec binds the complete APER value type.
func ERABSetupListBearerSUResCodec() s17.ERABSetupListBearerSUResValueCodec {
	return ERABSetupResponseIEs().ERABSetupListBearerSURes().Codec()
}

// ERABToBeModifiedListBearerModIndCodec binds the complete APER value type.
func ERABToBeModifiedListBearerModIndCodec() s17.ERABToBeModifiedListBearerModIndValueCodec {
	return ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Codec()
}

// HandoverFlagCodec binds the complete APER value type.
func HandoverFlagCodec() s00.HandoverFlagValueCodec {
	return SecondaryRATDataUsageReportIEs().HandoverFlag().Codec()
}

// InformationOnRecommendedCellsAndENBsForPagingCodec binds the complete APER value type.
func InformationOnRecommendedCellsAndENBsForPagingCodec() s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Codec()
}

// SecondaryRATDataUsageReportListCodec binds the complete APER value type.
func SecondaryRATDataUsageReportListCodec() s28.SecondaryRATDataUsageReportListValueCodec {
	return ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Codec()
}

// TimeSinceSecondaryNodeReleaseCodec binds the complete APER value type.
func TimeSinceSecondaryNodeReleaseCodec() s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Codec()
}

// TunnelInformationCodec binds the complete APER value type.
func TunnelInformationCodec() s35.TunnelInformationValueCodec {
	return ERABModificationIndicationIEs().TunnelInformationForBBF().Codec()
}
func BridgeERABModificationIndicationIETableMethodInfoCSGMembershipInfo(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoCSGMembershipInfo()
}
func BridgeERABModificationIndicationIETableMethodInfoENBUES1APID(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABModificationIndicationIETableMethodInfoERABNotToBeModifiedListBearerModInd(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoERABNotToBeModifiedListBearerModInd()
}
func BridgeERABModificationIndicationIETableMethodInfoERABToBeModifiedListBearerModInd(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoERABToBeModifiedListBearerModInd()
}
func BridgeERABModificationIndicationIETableMethodInfoMMEUES1APID(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABModificationIndicationIETableMethodInfoSecondaryRATDataUsageReportList(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeERABModificationIndicationIETableMethodInfoTunnelInformationForBBF(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoTunnelInformationForBBF()
}
func BridgeERABModificationIndicationIETableMethodInfoUserLocationInformation(v ERABModificationIndicationIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeERABModificationIndicationUserLocationInformationIEBindingFieldCodec(v *ERABModificationIndicationUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationUserLocationInformationIEBindingFieldGet(v *ERABModificationIndicationUserLocationInformationIEBinding) *func(*s44.ERABModificationIndicationIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeERABModificationIndicationUserLocationInformationIEBindingFieldInfo(v *ERABModificationIndicationUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationUserLocationInformationIEBindingFieldInject(v *ERABModificationIndicationUserLocationInformationIEBinding) *func(s44.UserLocationInformation) s44.ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldCodec(v *ERABModifyResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldGet(v *ERABModifyResponseCriticalityDiagnosticsIEBinding) *func(*ERABModifyResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldInfo(v *ERABModifyResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldInject(v *ERABModifyResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseENBUES1APIDIEBindingFieldCodec(v *ERABModifyResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseENBUES1APIDIEBindingFieldGet(v *ERABModifyResponseENBUES1APIDIEBinding) *func(*ERABModifyResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABModifyResponseENBUES1APIDIEBindingFieldInfo(v *ERABModifyResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseENBUES1APIDIEBindingFieldInject(v *ERABModifyResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseERABListIEBindingFieldCodec(v *ERABModifyResponseERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseERABListIEBindingFieldGet(v *ERABModifyResponseERABListIEBinding) *func(*ERABModifyResponseIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABModifyResponseERABListIEBindingFieldInfo(v *ERABModifyResponseERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseERABListIEBindingFieldInject(v *ERABModifyResponseERABListIEBinding) *func(s16.ERABList) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldCodec(v *ERABModifyResponseERABModifyListBearerModResIEBinding) *s16.ERABModifyListBearerModResValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldGet(v *ERABModifyResponseERABModifyListBearerModResIEBinding) *func(*ERABModifyResponseIEValue) (*s16.ERABModifyListBearerModRes, bool) {
	return &v.get
}
func BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldInfo(v *ERABModifyResponseERABModifyListBearerModResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldInject(v *ERABModifyResponseERABModifyListBearerModResIEBinding) *func(s16.ERABModifyListBearerModRes) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseIEContainerAPERValueFieldContext(v *ERABModifyResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEContainerAPERValueFieldReceived(v *ERABModifyResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEContainerAPERValueFieldReplay(v *ERABModifyResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEContainerAPERValueFieldWithoutReplay(v *ERABModifyResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEContainerValueCodecFieldCapture(v *ERABModifyResponseIEContainerValueCodec) *func(ERABModifyResponseIEContainer, aper.DecodeState) (ERABModifyResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseIEContainerValueCodecFieldCompare(v *ERABModifyResponseIEContainerValueCodec) *func(ERABModifyResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseIEContainerValueCodecFieldContext(v *ERABModifyResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEContainerValueCodecFieldDecode(v *ERABModifyResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponseIEContainer, error) {
	return &v.decode
}
func BridgeERABModifyResponseIEContainerValueCodecFieldEncode(v *ERABModifyResponseIEContainerValueCodec) *func(ERABModifyResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseIEContainerValueCodecFieldPath(v *ERABModifyResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseIEContainerValueCodecMethodEncodeBudgetValue(v ERABModifyResponseIEContainerValueCodec, a0 ERABModifyResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyResponseIEContainerValueCodecMethodEncodeChanged(v ERABModifyResponseIEContainerValueCodec, a0 ERABModifyResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyResponseIEFieldAPERValueFieldContext(v *ERABModifyResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEFieldAPERValueFieldReceived(v *ERABModifyResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEFieldAPERValueFieldReplay(v *ERABModifyResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEFieldAPERValueFieldWithoutReplay(v *ERABModifyResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEFieldFieldReceived(v *ERABModifyResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModifyResponseIEFieldFieldReplay(v *ERABModifyResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEFieldFieldStream(v *ERABModifyResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyResponseIEFieldFieldWithoutReplay(v *ERABModifyResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(v *ERABModifyResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(v *ERABModifyResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyResponseIEFieldValueCodecFieldCapture(v *ERABModifyResponseIEFieldValueCodec) *func(ERABModifyResponseIEField, aper.DecodeState) (ERABModifyResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseIEFieldValueCodecFieldCompare(v *ERABModifyResponseIEFieldValueCodec) *func(ERABModifyResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseIEFieldValueCodecFieldContext(v *ERABModifyResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEFieldValueCodecFieldDecode(v *ERABModifyResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponseIEField, error) {
	return &v.decode
}
func BridgeERABModifyResponseIEFieldValueCodecFieldEncode(v *ERABModifyResponseIEFieldValueCodec) *func(ERABModifyResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseIEFieldValueCodecFieldPath(v *ERABModifyResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseIEFieldValueCodecMethodEncodeBudgetValue(v ERABModifyResponseIEFieldValueCodec, a0 ERABModifyResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyResponseIEFieldValueCodecMethodEncodeChanged(v ERABModifyResponseIEFieldValueCodec, a0 ERABModifyResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyResponseIETableMethodInfoCriticalityDiagnostics(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeERABModifyResponseIETableMethodInfoENBUES1APID(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABModifyResponseIETableMethodInfoERABFailedToModifyList(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoERABFailedToModifyList()
}
func BridgeERABModifyResponseIETableMethodInfoERABModifyListBearerModRes(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoERABModifyListBearerModRes()
}
func BridgeERABModifyResponseIETableMethodInfoMMEUES1APID(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABModifyResponseIETableMethodInfoSecondaryRATDataUsageReportList(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeERABModifyResponseIETableMethodInfoUserLocationInformation(v ERABModifyResponseIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeERABModifyResponseIEValueERABIEContainerListAPERValueFieldContext(v *ERABModifyResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModifyResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModifyResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *func(ERABModifyResponseIEValueERABIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *func(ERABModifyResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldContext(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *func(ERABModifyResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldPath(v *ERABModifyResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyResponseIEValueERABIEContainerListValueCodec, a0 ERABModifyResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModifyResponseIEValueERABIEContainerListValueCodec, a0 ERABModifyResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyResponseIEValueFieldId(v *ERABModifyResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModifyResponseIEValueFieldIsOpaque(v *ERABModifyResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModifyResponseIEValueFieldOpaque(v *ERABModifyResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModifyResponseIEValueFieldReceived(v *ERABModifyResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEValueFieldReplay(v *ERABModifyResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEValueFieldRowCriticalityDiagnostics(v *ERABModifyResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeERABModifyResponseIEValueFieldRowENBUES1APID(v *ERABModifyResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABModifyResponseIEValueFieldRowERABFailedToModifyList(v *ERABModifyResponseIEValue) **s16.ERABList {
	return &v.rowERABFailedToModifyList
}
func BridgeERABModifyResponseIEValueFieldRowERABModifyListBearerModRes(v *ERABModifyResponseIEValue) **s16.ERABModifyListBearerModRes {
	return &v.rowERABModifyListBearerModRes
}
func BridgeERABModifyResponseIEValueFieldRowMMEUES1APID(v *ERABModifyResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABModifyResponseIEValueFieldRowSecondaryRATDataUsageReportList(v *ERABModifyResponseIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeERABModifyResponseIEValueFieldRowUserLocationInformation(v *ERABModifyResponseIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeERABModifyResponseIEValueMethodCaptureSemantics(v ERABModifyResponseIEValue, a0 aper.SemanticCapture) ERABModifyResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModifyResponseIEValueMethodCompareSemantics(v ERABModifyResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModifyResponseIEValueMethodDecode(v ERABModifyResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModifyResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModifyResponseIEValueMethodEncode(v ERABModifyResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModifyResponseIEValueMethodEncodeFresh(v ERABModifyResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModifyResponseIEValueMethodMatchesID(v ERABModifyResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModifyResponseIEValueMethodReason(v ERABModifyResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModifyResponseIEValueMethodRule(v ERABModifyResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModifyResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModifyResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModifyResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *func(ERABModifyResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModifyResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyResponseIEValueProtocolIEContainerListValueCodec, a0 ERABModifyResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModifyResponseIEValueProtocolIEContainerListValueCodec, a0 ERABModifyResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyResponseMMEUES1APIDIEBindingFieldCodec(v *ERABModifyResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseMMEUES1APIDIEBindingFieldGet(v *ERABModifyResponseMMEUES1APIDIEBinding) *func(*ERABModifyResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABModifyResponseMMEUES1APIDIEBindingFieldInfo(v *ERABModifyResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseMMEUES1APIDIEBindingFieldInject(v *ERABModifyResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldCodec(v *ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldGet(v *ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) *func(*ERABModifyResponseIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldInfo(v *ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldInject(v *ERABModifyResponseSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABModifyResponseUserLocationInformationIEBindingFieldCodec(v *ERABModifyResponseUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeERABModifyResponseUserLocationInformationIEBindingFieldGet(v *ERABModifyResponseUserLocationInformationIEBinding) *func(*ERABModifyResponseIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeERABModifyResponseUserLocationInformationIEBindingFieldInfo(v *ERABModifyResponseUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyResponseUserLocationInformationIEBindingFieldInject(v *ERABModifyResponseUserLocationInformationIEBinding) *func(s44.UserLocationInformation) ERABModifyResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldCodec(v *ERABReleaseIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldGet(v *ERABReleaseIndicationENBUES1APIDIEBinding) *func(*ERABReleaseIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldInfo(v *ERABReleaseIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldInject(v *ERABReleaseIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABReleaseIndicationIEValue {
	return &v.inject
}
func BridgeERABReleaseIndicationERABListIEBindingFieldCodec(v *ERABReleaseIndicationERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABReleaseIndicationERABListIEBindingFieldGet(v *ERABReleaseIndicationERABListIEBinding) *func(*ERABReleaseIndicationIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABReleaseIndicationERABListIEBindingFieldInfo(v *ERABReleaseIndicationERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseIndicationERABListIEBindingFieldInject(v *ERABReleaseIndicationERABListIEBinding) *func(s16.ERABList) ERABReleaseIndicationIEValue {
	return &v.inject
}
func BridgeERABReleaseIndicationIEContainerAPERValueFieldContext(v *ERABReleaseIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEContainerAPERValueFieldReceived(v *ERABReleaseIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEContainerAPERValueFieldReplay(v *ERABReleaseIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEContainerAPERValueFieldWithoutReplay(v *ERABReleaseIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldCapture(v *ERABReleaseIndicationIEContainerValueCodec) *func(ERABReleaseIndicationIEContainer, aper.DecodeState) (ERABReleaseIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldCompare(v *ERABReleaseIndicationIEContainerValueCodec) *func(ERABReleaseIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldContext(v *ERABReleaseIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldDecode(v *ERABReleaseIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndicationIEContainer, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldEncode(v *ERABReleaseIndicationIEContainerValueCodec) *func(ERABReleaseIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationIEContainerValueCodecFieldPath(v *ERABReleaseIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ERABReleaseIndicationIEContainerValueCodec, a0 ERABReleaseIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseIndicationIEContainerValueCodecMethodEncodeChanged(v ERABReleaseIndicationIEContainerValueCodec, a0 ERABReleaseIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseIndicationIEFieldAPERValueFieldContext(v *ERABReleaseIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEFieldAPERValueFieldReceived(v *ERABReleaseIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEFieldAPERValueFieldReplay(v *ERABReleaseIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEFieldAPERValueFieldWithoutReplay(v *ERABReleaseIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEFieldFieldReceived(v *ERABReleaseIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABReleaseIndicationIEFieldFieldReplay(v *ERABReleaseIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEFieldFieldStream(v *ERABReleaseIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseIndicationIEFieldFieldWithoutReplay(v *ERABReleaseIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(v *ERABReleaseIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(v *ERABReleaseIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldCapture(v *ERABReleaseIndicationIEFieldValueCodec) *func(ERABReleaseIndicationIEField, aper.DecodeState) (ERABReleaseIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldCompare(v *ERABReleaseIndicationIEFieldValueCodec) *func(ERABReleaseIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldContext(v *ERABReleaseIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldDecode(v *ERABReleaseIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndicationIEField, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldEncode(v *ERABReleaseIndicationIEFieldValueCodec) *func(ERABReleaseIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationIEFieldValueCodecFieldPath(v *ERABReleaseIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ERABReleaseIndicationIEFieldValueCodec, a0 ERABReleaseIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseIndicationIEFieldValueCodecMethodEncodeChanged(v ERABReleaseIndicationIEFieldValueCodec, a0 ERABReleaseIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseIndicationIETableMethodInfoENBUES1APID(v ERABReleaseIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABReleaseIndicationIETableMethodInfoERABReleasedList(v ERABReleaseIndicationIETable) s00.FieldInfo {
	return v.infoERABReleasedList()
}
func BridgeERABReleaseIndicationIETableMethodInfoMMEUES1APID(v ERABReleaseIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABReleaseIndicationIETableMethodInfoSecondaryRATDataUsageReportList(v ERABReleaseIndicationIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeERABReleaseIndicationIETableMethodInfoUserLocationInformation(v ERABReleaseIndicationIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ERABReleaseIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ERABReleaseIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ERABReleaseIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ERABReleaseIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseIndicationIEValueERABIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseIndicationIEValueERABIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseIndicationIEValueFieldId(v *ERABReleaseIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABReleaseIndicationIEValueFieldIsOpaque(v *ERABReleaseIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABReleaseIndicationIEValueFieldOpaque(v *ERABReleaseIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABReleaseIndicationIEValueFieldReceived(v *ERABReleaseIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEValueFieldReplay(v *ERABReleaseIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEValueFieldRowENBUES1APID(v *ERABReleaseIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABReleaseIndicationIEValueFieldRowERABReleasedList(v *ERABReleaseIndicationIEValue) **s16.ERABList {
	return &v.rowERABReleasedList
}
func BridgeERABReleaseIndicationIEValueFieldRowMMEUES1APID(v *ERABReleaseIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABReleaseIndicationIEValueFieldRowSecondaryRATDataUsageReportList(v *ERABReleaseIndicationIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeERABReleaseIndicationIEValueFieldRowUserLocationInformation(v *ERABReleaseIndicationIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeERABReleaseIndicationIEValueMethodCaptureSemantics(v ERABReleaseIndicationIEValue, a0 aper.SemanticCapture) ERABReleaseIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABReleaseIndicationIEValueMethodCompareSemantics(v ERABReleaseIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABReleaseIndicationIEValueMethodDecode(v ERABReleaseIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABReleaseIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABReleaseIndicationIEValueMethodEncode(v ERABReleaseIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABReleaseIndicationIEValueMethodEncodeFresh(v ERABReleaseIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABReleaseIndicationIEValueMethodMatchesID(v ERABReleaseIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABReleaseIndicationIEValueMethodReason(v ERABReleaseIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABReleaseIndicationIEValueMethodRule(v ERABReleaseIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldCodec(v *ERABReleaseIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldGet(v *ERABReleaseIndicationMMEUES1APIDIEBinding) *func(*ERABReleaseIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldInfo(v *ERABReleaseIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldInject(v *ERABReleaseIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABReleaseIndicationIEValue {
	return &v.inject
}
func BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldCodec(v *ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldGet(v *ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) *func(*ERABReleaseIndicationIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldInfo(v *ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldInject(v *ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) ERABReleaseIndicationIEValue {
	return &v.inject
}
func BridgeERABReleaseIndicationUserLocationInformationIEBindingFieldCodec(v *ERABReleaseIndicationUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeERABReleaseIndicationUserLocationInformationIEBindingFieldGet(v *ERABReleaseIndicationUserLocationInformationIEBinding) *func(*ERABReleaseIndicationIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeERABReleaseIndicationUserLocationInformationIEBindingFieldInfo(v *ERABReleaseIndicationUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseIndicationUserLocationInformationIEBindingFieldInject(v *ERABReleaseIndicationUserLocationInformationIEBinding) *func(s44.UserLocationInformation) ERABReleaseIndicationIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldCodec(v *ERABReleaseResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldGet(v *ERABReleaseResponseCriticalityDiagnosticsIEBinding) *func(*ERABReleaseResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldInfo(v *ERABReleaseResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldInject(v *ERABReleaseResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseENBUES1APIDIEBindingFieldCodec(v *ERABReleaseResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseENBUES1APIDIEBindingFieldGet(v *ERABReleaseResponseENBUES1APIDIEBinding) *func(*ERABReleaseResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseResponseENBUES1APIDIEBindingFieldInfo(v *ERABReleaseResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseENBUES1APIDIEBindingFieldInject(v *ERABReleaseResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseERABListIEBindingFieldCodec(v *ERABReleaseResponseERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseERABListIEBindingFieldGet(v *ERABReleaseResponseERABListIEBinding) *func(*ERABReleaseResponseIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABReleaseResponseERABListIEBindingFieldInfo(v *ERABReleaseResponseERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseERABListIEBindingFieldInject(v *ERABReleaseResponseERABListIEBinding) *func(s16.ERABList) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldCodec(v *ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) *s16.ERABReleaseListBearerRelCompValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldGet(v *ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) *func(*ERABReleaseResponseIEValue) (*s16.ERABReleaseListBearerRelComp, bool) {
	return &v.get
}
func BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldInfo(v *ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldInject(v *ERABReleaseResponseERABReleaseListBearerRelCompIEBinding) *func(s16.ERABReleaseListBearerRelComp) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseIEContainerAPERValueFieldContext(v *ERABReleaseResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEContainerAPERValueFieldReceived(v *ERABReleaseResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEContainerAPERValueFieldReplay(v *ERABReleaseResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEContainerAPERValueFieldWithoutReplay(v *ERABReleaseResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldCapture(v *ERABReleaseResponseIEContainerValueCodec) *func(ERABReleaseResponseIEContainer, aper.DecodeState) (ERABReleaseResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldCompare(v *ERABReleaseResponseIEContainerValueCodec) *func(ERABReleaseResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldContext(v *ERABReleaseResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(v *ERABReleaseResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponseIEContainer, error) {
	return &v.decode
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(v *ERABReleaseResponseIEContainerValueCodec) *func(ERABReleaseResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseIEContainerValueCodecFieldPath(v *ERABReleaseResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseIEContainerValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseIEContainerValueCodec, a0 ERABReleaseResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseIEContainerValueCodecMethodEncodeChanged(v ERABReleaseResponseIEContainerValueCodec, a0 ERABReleaseResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseResponseIEFieldAPERValueFieldContext(v *ERABReleaseResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEFieldAPERValueFieldReceived(v *ERABReleaseResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEFieldAPERValueFieldReplay(v *ERABReleaseResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEFieldAPERValueFieldWithoutReplay(v *ERABReleaseResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEFieldFieldReceived(v *ERABReleaseResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABReleaseResponseIEFieldFieldReplay(v *ERABReleaseResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEFieldFieldStream(v *ERABReleaseResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseResponseIEFieldFieldWithoutReplay(v *ERABReleaseResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(v *ERABReleaseResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(v *ERABReleaseResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldCapture(v *ERABReleaseResponseIEFieldValueCodec) *func(ERABReleaseResponseIEField, aper.DecodeState) (ERABReleaseResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldCompare(v *ERABReleaseResponseIEFieldValueCodec) *func(ERABReleaseResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldContext(v *ERABReleaseResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldDecode(v *ERABReleaseResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponseIEField, error) {
	return &v.decode
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldEncode(v *ERABReleaseResponseIEFieldValueCodec) *func(ERABReleaseResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseIEFieldValueCodecFieldPath(v *ERABReleaseResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseIEFieldValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseIEFieldValueCodec, a0 ERABReleaseResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseIEFieldValueCodecMethodEncodeChanged(v ERABReleaseResponseIEFieldValueCodec, a0 ERABReleaseResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseResponseIETableMethodInfoCriticalityDiagnostics(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeERABReleaseResponseIETableMethodInfoENBUES1APID(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABReleaseResponseIETableMethodInfoERABFailedToReleaseList(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoERABFailedToReleaseList()
}
func BridgeERABReleaseResponseIETableMethodInfoERABReleaseListBearerRelComp(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoERABReleaseListBearerRelComp()
}
func BridgeERABReleaseResponseIETableMethodInfoMMEUES1APID(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABReleaseResponseIETableMethodInfoSecondaryRATDataUsageReportList(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeERABReleaseResponseIETableMethodInfoUserLocationInformation(v ERABReleaseResponseIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeERABReleaseResponseIEValueERABIEContainerListAPERValueFieldContext(v *ERABReleaseResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueERABIEContainerListAPERValueFieldReceived(v *ERABReleaseResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEValueERABIEContainerListAPERValueFieldReplay(v *ERABReleaseResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCapture(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *func(ERABReleaseResponseIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCompare(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *func(ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldContext(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldDecode(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldEncode(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *func(ERABReleaseResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldPath(v *ERABReleaseResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseIEValueERABIEContainerListValueCodec, a0 ERABReleaseResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseResponseIEValueERABIEContainerListValueCodec, a0 ERABReleaseResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseResponseIEValueFieldId(v *ERABReleaseResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABReleaseResponseIEValueFieldIsOpaque(v *ERABReleaseResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABReleaseResponseIEValueFieldOpaque(v *ERABReleaseResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABReleaseResponseIEValueFieldReceived(v *ERABReleaseResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEValueFieldReplay(v *ERABReleaseResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEValueFieldRowCriticalityDiagnostics(v *ERABReleaseResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeERABReleaseResponseIEValueFieldRowENBUES1APID(v *ERABReleaseResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABReleaseResponseIEValueFieldRowERABFailedToReleaseList(v *ERABReleaseResponseIEValue) **s16.ERABList {
	return &v.rowERABFailedToReleaseList
}
func BridgeERABReleaseResponseIEValueFieldRowERABReleaseListBearerRelComp(v *ERABReleaseResponseIEValue) **s16.ERABReleaseListBearerRelComp {
	return &v.rowERABReleaseListBearerRelComp
}
func BridgeERABReleaseResponseIEValueFieldRowMMEUES1APID(v *ERABReleaseResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABReleaseResponseIEValueFieldRowSecondaryRATDataUsageReportList(v *ERABReleaseResponseIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeERABReleaseResponseIEValueFieldRowUserLocationInformation(v *ERABReleaseResponseIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeERABReleaseResponseIEValueMethodCaptureSemantics(v ERABReleaseResponseIEValue, a0 aper.SemanticCapture) ERABReleaseResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABReleaseResponseIEValueMethodCompareSemantics(v ERABReleaseResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABReleaseResponseIEValueMethodDecode(v ERABReleaseResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABReleaseResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABReleaseResponseIEValueMethodEncode(v ERABReleaseResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABReleaseResponseIEValueMethodEncodeFresh(v ERABReleaseResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABReleaseResponseIEValueMethodMatchesID(v ERABReleaseResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABReleaseResponseIEValueMethodReason(v ERABReleaseResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABReleaseResponseIEValueMethodRule(v ERABReleaseResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABReleaseResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseResponseIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldCodec(v *ERABReleaseResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldGet(v *ERABReleaseResponseMMEUES1APIDIEBinding) *func(*ERABReleaseResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldInfo(v *ERABReleaseResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldInject(v *ERABReleaseResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldCodec(v *ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldGet(v *ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) *func(*ERABReleaseResponseIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldInfo(v *ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldInject(v *ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABReleaseResponseUserLocationInformationIEBindingFieldCodec(v *ERABReleaseResponseUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeERABReleaseResponseUserLocationInformationIEBindingFieldGet(v *ERABReleaseResponseUserLocationInformationIEBinding) *func(*ERABReleaseResponseIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeERABReleaseResponseUserLocationInformationIEBindingFieldInfo(v *ERABReleaseResponseUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseResponseUserLocationInformationIEBindingFieldInject(v *ERABReleaseResponseUserLocationInformationIEBinding) *func(s44.UserLocationInformation) ERABReleaseResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldCodec(v *ERABSetupResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldGet(v *ERABSetupResponseCriticalityDiagnosticsIEBinding) *func(*ERABSetupResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldInfo(v *ERABSetupResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldInject(v *ERABSetupResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseENBUES1APIDIEBindingFieldCodec(v *ERABSetupResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseENBUES1APIDIEBindingFieldGet(v *ERABSetupResponseENBUES1APIDIEBinding) *func(*ERABSetupResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABSetupResponseENBUES1APIDIEBindingFieldInfo(v *ERABSetupResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseENBUES1APIDIEBindingFieldInject(v *ERABSetupResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseERABListIEBindingFieldCodec(v *ERABSetupResponseERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseERABListIEBindingFieldGet(v *ERABSetupResponseERABListIEBinding) *func(*ERABSetupResponseIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABSetupResponseERABListIEBindingFieldInfo(v *ERABSetupResponseERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseERABListIEBindingFieldInject(v *ERABSetupResponseERABListIEBinding) *func(s16.ERABList) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldCodec(v *ERABSetupResponseERABSetupListBearerSUResIEBinding) *s17.ERABSetupListBearerSUResValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldGet(v *ERABSetupResponseERABSetupListBearerSUResIEBinding) *func(*ERABSetupResponseIEValue) (*s17.ERABSetupListBearerSURes, bool) {
	return &v.get
}
func BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldInfo(v *ERABSetupResponseERABSetupListBearerSUResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldInject(v *ERABSetupResponseERABSetupListBearerSUResIEBinding) *func(s17.ERABSetupListBearerSURes) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseIEContainerAPERValueFieldContext(v *ERABSetupResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEContainerAPERValueFieldReceived(v *ERABSetupResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEContainerAPERValueFieldReplay(v *ERABSetupResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEContainerAPERValueFieldWithoutReplay(v *ERABSetupResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEContainerValueCodecFieldCapture(v *ERABSetupResponseIEContainerValueCodec) *func(ERABSetupResponseIEContainer, aper.DecodeState) (ERABSetupResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseIEContainerValueCodecFieldCompare(v *ERABSetupResponseIEContainerValueCodec) *func(ERABSetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseIEContainerValueCodecFieldContext(v *ERABSetupResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEContainerValueCodecFieldDecode(v *ERABSetupResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponseIEContainer, error) {
	return &v.decode
}
func BridgeERABSetupResponseIEContainerValueCodecFieldEncode(v *ERABSetupResponseIEContainerValueCodec) *func(ERABSetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseIEContainerValueCodecFieldPath(v *ERABSetupResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseIEContainerValueCodecMethodEncodeBudgetValue(v ERABSetupResponseIEContainerValueCodec, a0 ERABSetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseIEContainerValueCodecMethodEncodeChanged(v ERABSetupResponseIEContainerValueCodec, a0 ERABSetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseIEFieldAPERValueFieldContext(v *ERABSetupResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEFieldAPERValueFieldReceived(v *ERABSetupResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEFieldAPERValueFieldReplay(v *ERABSetupResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEFieldAPERValueFieldWithoutReplay(v *ERABSetupResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEFieldFieldReceived(v *ERABSetupResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABSetupResponseIEFieldFieldReplay(v *ERABSetupResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEFieldFieldStream(v *ERABSetupResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupResponseIEFieldFieldWithoutReplay(v *ERABSetupResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(v *ERABSetupResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(v *ERABSetupResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupResponseIEFieldValueCodecFieldCapture(v *ERABSetupResponseIEFieldValueCodec) *func(ERABSetupResponseIEField, aper.DecodeState) (ERABSetupResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseIEFieldValueCodecFieldCompare(v *ERABSetupResponseIEFieldValueCodec) *func(ERABSetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseIEFieldValueCodecFieldContext(v *ERABSetupResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEFieldValueCodecFieldDecode(v *ERABSetupResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponseIEField, error) {
	return &v.decode
}
func BridgeERABSetupResponseIEFieldValueCodecFieldEncode(v *ERABSetupResponseIEFieldValueCodec) *func(ERABSetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseIEFieldValueCodecFieldPath(v *ERABSetupResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseIEFieldValueCodecMethodEncodeBudgetValue(v ERABSetupResponseIEFieldValueCodec, a0 ERABSetupResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseIEFieldValueCodecMethodEncodeChanged(v ERABSetupResponseIEFieldValueCodec, a0 ERABSetupResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseIETableMethodInfoCriticalityDiagnostics(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeERABSetupResponseIETableMethodInfoENBUES1APID(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABSetupResponseIETableMethodInfoERABFailedToSetupListBearerSURes(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoERABFailedToSetupListBearerSURes()
}
func BridgeERABSetupResponseIETableMethodInfoERABSetupListBearerSURes(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoERABSetupListBearerSURes()
}
func BridgeERABSetupResponseIETableMethodInfoMMEUES1APID(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABSetupResponseIETableMethodInfoUserLocationInformation(v ERABSetupResponseIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeERABSetupResponseIEValueERABIEContainerListAPERValueFieldContext(v *ERABSetupResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueERABIEContainerListAPERValueFieldReceived(v *ERABSetupResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEValueERABIEContainerListAPERValueFieldReplay(v *ERABSetupResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCapture(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *func(ERABSetupResponseIEValueERABIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCompare(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *func(ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldContext(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldDecode(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldEncode(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *func(ERABSetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldPath(v *ERABSetupResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupResponseIEValueERABIEContainerListValueCodec, a0 ERABSetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABSetupResponseIEValueERABIEContainerListValueCodec, a0 ERABSetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseIEValueFieldId(v *ERABSetupResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABSetupResponseIEValueFieldIsOpaque(v *ERABSetupResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABSetupResponseIEValueFieldOpaque(v *ERABSetupResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABSetupResponseIEValueFieldReceived(v *ERABSetupResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEValueFieldReplay(v *ERABSetupResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEValueFieldRowCriticalityDiagnostics(v *ERABSetupResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeERABSetupResponseIEValueFieldRowENBUES1APID(v *ERABSetupResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABSetupResponseIEValueFieldRowERABFailedToSetupListBearerSURes(v *ERABSetupResponseIEValue) **s16.ERABList {
	return &v.rowERABFailedToSetupListBearerSURes
}
func BridgeERABSetupResponseIEValueFieldRowERABSetupListBearerSURes(v *ERABSetupResponseIEValue) **s17.ERABSetupListBearerSURes {
	return &v.rowERABSetupListBearerSURes
}
func BridgeERABSetupResponseIEValueFieldRowMMEUES1APID(v *ERABSetupResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABSetupResponseIEValueFieldRowUserLocationInformation(v *ERABSetupResponseIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeERABSetupResponseIEValueMethodCaptureSemantics(v ERABSetupResponseIEValue, a0 aper.SemanticCapture) ERABSetupResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABSetupResponseIEValueMethodCompareSemantics(v ERABSetupResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABSetupResponseIEValueMethodDecode(v ERABSetupResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABSetupResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABSetupResponseIEValueMethodEncode(v ERABSetupResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABSetupResponseIEValueMethodEncodeFresh(v ERABSetupResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABSetupResponseIEValueMethodMatchesID(v ERABSetupResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABSetupResponseIEValueMethodReason(v ERABSetupResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABSetupResponseIEValueMethodRule(v ERABSetupResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABSetupResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABSetupResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABSetupResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *func(ERABSetupResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABSetupResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupResponseIEValueProtocolIEContainerListValueCodec, a0 ERABSetupResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABSetupResponseIEValueProtocolIEContainerListValueCodec, a0 ERABSetupResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseMMEUES1APIDIEBindingFieldCodec(v *ERABSetupResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseMMEUES1APIDIEBindingFieldGet(v *ERABSetupResponseMMEUES1APIDIEBinding) *func(*ERABSetupResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABSetupResponseMMEUES1APIDIEBindingFieldInfo(v *ERABSetupResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseMMEUES1APIDIEBindingFieldInject(v *ERABSetupResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeERABSetupResponseUserLocationInformationIEBindingFieldCodec(v *ERABSetupResponseUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeERABSetupResponseUserLocationInformationIEBindingFieldGet(v *ERABSetupResponseUserLocationInformationIEBinding) *func(*ERABSetupResponseIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeERABSetupResponseUserLocationInformationIEBindingFieldInfo(v *ERABSetupResponseUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupResponseUserLocationInformationIEBindingFieldInject(v *ERABSetupResponseUserLocationInformationIEBinding) *func(s44.UserLocationInformation) ERABSetupResponseIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldCodec(v *SecondaryRATDataUsageReportENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldGet(v *SecondaryRATDataUsageReportENBUES1APIDIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldInfo(v *SecondaryRATDataUsageReportENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldInject(v *SecondaryRATDataUsageReportENBUES1APIDIEBinding) *func(s00.ENBUES1APID) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldCodec(v *SecondaryRATDataUsageReportHandoverFlagIEBinding) *s00.HandoverFlagValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldGet(v *SecondaryRATDataUsageReportHandoverFlagIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s00.HandoverFlag, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldInfo(v *SecondaryRATDataUsageReportHandoverFlagIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldInject(v *SecondaryRATDataUsageReportHandoverFlagIEBinding) *func(s00.HandoverFlag) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportIEContainerAPERValueFieldContext(v *SecondaryRATDataUsageReportIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEContainerAPERValueFieldReceived(v *SecondaryRATDataUsageReportIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEContainerAPERValueFieldReplay(v *SecondaryRATDataUsageReportIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEContainerAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCapture(v *SecondaryRATDataUsageReportIEContainerValueCodec) *func(SecondaryRATDataUsageReportIEContainer, aper.DecodeState) (SecondaryRATDataUsageReportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCompare(v *SecondaryRATDataUsageReportIEContainerValueCodec) *func(SecondaryRATDataUsageReportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldContext(v *SecondaryRATDataUsageReportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(v *SecondaryRATDataUsageReportIEContainerValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEContainer, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(v *SecondaryRATDataUsageReportIEContainerValueCodec) *func(SecondaryRATDataUsageReportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldPath(v *SecondaryRATDataUsageReportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportIEContainerValueCodec, a0 SecondaryRATDataUsageReportIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportIEContainerValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportIEContainerValueCodec, a0 SecondaryRATDataUsageReportIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportIEFieldAPERValueFieldContext(v *SecondaryRATDataUsageReportIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEFieldAPERValueFieldReceived(v *SecondaryRATDataUsageReportIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEFieldAPERValueFieldReplay(v *SecondaryRATDataUsageReportIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEFieldAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEFieldFieldReceived(v *SecondaryRATDataUsageReportIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEFieldFieldReplay(v *SecondaryRATDataUsageReportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEFieldFieldStream(v *SecondaryRATDataUsageReportIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSecondaryRATDataUsageReportIEFieldFieldWithoutReplay(v *SecondaryRATDataUsageReportIEField) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(v *SecondaryRATDataUsageReportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCapture(v *SecondaryRATDataUsageReportIEFieldValueCodec) *func(SecondaryRATDataUsageReportIEField, aper.DecodeState) (SecondaryRATDataUsageReportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCompare(v *SecondaryRATDataUsageReportIEFieldValueCodec) *func(SecondaryRATDataUsageReportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldContext(v *SecondaryRATDataUsageReportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldDecode(v *SecondaryRATDataUsageReportIEFieldValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEField, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldEncode(v *SecondaryRATDataUsageReportIEFieldValueCodec) *func(SecondaryRATDataUsageReportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldPath(v *SecondaryRATDataUsageReportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportIEFieldValueCodec, a0 SecondaryRATDataUsageReportIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportIEFieldValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportIEFieldValueCodec, a0 SecondaryRATDataUsageReportIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoENBUES1APID(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoHandoverFlag(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoHandoverFlag()
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoMMEUES1APID(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoSecondaryRATDataUsageReportList(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoTimeSinceSecondaryNodeRelease(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoTimeSinceSecondaryNodeRelease()
}
func BridgeSecondaryRATDataUsageReportIETableMethodInfoUserLocationInformation(v SecondaryRATDataUsageReportIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportIEValueFieldId(v *SecondaryRATDataUsageReportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSecondaryRATDataUsageReportIEValueFieldIsOpaque(v *SecondaryRATDataUsageReportIEValue) *bool {
	return &v.isOpaque
}
func BridgeSecondaryRATDataUsageReportIEValueFieldOpaque(v *SecondaryRATDataUsageReportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSecondaryRATDataUsageReportIEValueFieldReceived(v *SecondaryRATDataUsageReportIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEValueFieldReplay(v *SecondaryRATDataUsageReportIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowENBUES1APID(v *SecondaryRATDataUsageReportIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowHandoverFlag(v *SecondaryRATDataUsageReportIEValue) **s00.HandoverFlag {
	return &v.rowHandoverFlag
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowMMEUES1APID(v *SecondaryRATDataUsageReportIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowSecondaryRATDataUsageReportList(v *SecondaryRATDataUsageReportIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowTimeSinceSecondaryNodeRelease(v *SecondaryRATDataUsageReportIEValue) **s00.TimeSinceSecondaryNodeRelease {
	return &v.rowTimeSinceSecondaryNodeRelease
}
func BridgeSecondaryRATDataUsageReportIEValueFieldRowUserLocationInformation(v *SecondaryRATDataUsageReportIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeSecondaryRATDataUsageReportIEValueMethodCaptureSemantics(v SecondaryRATDataUsageReportIEValue, a0 aper.SemanticCapture) SecondaryRATDataUsageReportIEValue {
	return v.captureSemantics(a0)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodCompareSemantics(v SecondaryRATDataUsageReportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodDecode(v SecondaryRATDataUsageReportIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SecondaryRATDataUsageReportIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodEncode(v SecondaryRATDataUsageReportIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh(v SecondaryRATDataUsageReportIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodMatchesID(v SecondaryRATDataUsageReportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodReason(v SecondaryRATDataUsageReportIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSecondaryRATDataUsageReportIEValueMethodRule(v SecondaryRATDataUsageReportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec, a0 SecondaryRATDataUsageReportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldCodec(v *SecondaryRATDataUsageReportMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldGet(v *SecondaryRATDataUsageReportMMEUES1APIDIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldInfo(v *SecondaryRATDataUsageReportMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldInject(v *SecondaryRATDataUsageReportMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldCodec(v *SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldGet(v *SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldInfo(v *SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldInject(v *SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(v *SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) *s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldGet(v *SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(v *SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldInject(v *SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding) *func(s00.TimeSinceSecondaryNodeRelease) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportUserLocationInformationIEBindingFieldCodec(v *SecondaryRATDataUsageReportUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportUserLocationInformationIEBindingFieldGet(v *SecondaryRATDataUsageReportUserLocationInformationIEBinding) *func(*SecondaryRATDataUsageReportIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportUserLocationInformationIEBindingFieldInfo(v *SecondaryRATDataUsageReportUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportUserLocationInformationIEBindingFieldInject(v *SecondaryRATDataUsageReportUserLocationInformationIEBinding) *func(s44.UserLocationInformation) SecondaryRATDataUsageReportIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldCodec(v *UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) *s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldGet(v *UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s17.CellIdentifierAndCELevelForCECapableUEs, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInfo(v *UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInject(v *UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding) *func(s17.CellIdentifierAndCELevelForCECapableUEs) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldGet(v *UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldInject(v *UEContextReleaseCompleteCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldCodec(v *UEContextReleaseCompleteENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldGet(v *UEContextReleaseCompleteENBUES1APIDIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldInfo(v *UEContextReleaseCompleteENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldInject(v *UEContextReleaseCompleteENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteIEContainerAPERValueFieldContext(v *UEContextReleaseCompleteIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEContainerAPERValueFieldReceived(v *UEContextReleaseCompleteIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEContainerAPERValueFieldReplay(v *UEContextReleaseCompleteIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEContainerAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCapture(v *UEContextReleaseCompleteIEContainerValueCodec) *func(UEContextReleaseCompleteIEContainer, aper.DecodeState) (UEContextReleaseCompleteIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCompare(v *UEContextReleaseCompleteIEContainerValueCodec) *func(UEContextReleaseCompleteIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldContext(v *UEContextReleaseCompleteIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(v *UEContextReleaseCompleteIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEContainer, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(v *UEContextReleaseCompleteIEContainerValueCodec) *func(UEContextReleaseCompleteIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecFieldPath(v *UEContextReleaseCompleteIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteIEContainerValueCodec, a0 UEContextReleaseCompleteIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteIEContainerValueCodecMethodEncodeChanged(v UEContextReleaseCompleteIEContainerValueCodec, a0 UEContextReleaseCompleteIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCompleteIEFieldAPERValueFieldContext(v *UEContextReleaseCompleteIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEFieldAPERValueFieldReceived(v *UEContextReleaseCompleteIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEFieldAPERValueFieldReplay(v *UEContextReleaseCompleteIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEFieldAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEFieldFieldReceived(v *UEContextReleaseCompleteIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEFieldFieldReplay(v *UEContextReleaseCompleteIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEFieldFieldStream(v *UEContextReleaseCompleteIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCompleteIEFieldFieldWithoutReplay(v *UEContextReleaseCompleteIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(v *UEContextReleaseCompleteIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(v *UEContextReleaseCompleteIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCapture(v *UEContextReleaseCompleteIEFieldValueCodec) *func(UEContextReleaseCompleteIEField, aper.DecodeState) (UEContextReleaseCompleteIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCompare(v *UEContextReleaseCompleteIEFieldValueCodec) *func(UEContextReleaseCompleteIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldContext(v *UEContextReleaseCompleteIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldDecode(v *UEContextReleaseCompleteIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEField, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldEncode(v *UEContextReleaseCompleteIEFieldValueCodec) *func(UEContextReleaseCompleteIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecFieldPath(v *UEContextReleaseCompleteIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteIEFieldValueCodec, a0 UEContextReleaseCompleteIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteIEFieldValueCodecMethodEncodeChanged(v UEContextReleaseCompleteIEFieldValueCodec, a0 UEContextReleaseCompleteIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCompleteIETableMethodInfoCellIdentifierAndCELevelForCECapableUEs(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoCellIdentifierAndCELevelForCECapableUEs()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoCriticalityDiagnostics(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoENBUES1APID(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoInformationOnRecommendedCellsAndENBsForPaging(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoInformationOnRecommendedCellsAndENBsForPaging()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoMMEUES1APID(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoSecondaryRATDataUsageReportList(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoTimeSinceSecondaryNodeRelease(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoTimeSinceSecondaryNodeRelease()
}
func BridgeUEContextReleaseCompleteIETableMethodInfoUserLocationInformation(v UEContextReleaseCompleteIETable) s00.FieldInfo {
	return v.infoUserLocationInformation()
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListAPERValueFieldContext(v *UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldContext(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldPath(v *UEContextReleaseCompleteIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCompleteIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCompleteIEValueFieldId(v *UEContextReleaseCompleteIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextReleaseCompleteIEValueFieldIsOpaque(v *UEContextReleaseCompleteIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextReleaseCompleteIEValueFieldOpaque(v *UEContextReleaseCompleteIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextReleaseCompleteIEValueFieldReceived(v *UEContextReleaseCompleteIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEValueFieldReplay(v *UEContextReleaseCompleteIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(v *UEContextReleaseCompleteIEValue) **s17.CellIdentifierAndCELevelForCECapableUEs {
	return &v.rowCellIdentifierAndCELevelForCECapableUEs
}
func BridgeUEContextReleaseCompleteIEValueFieldRowCriticalityDiagnostics(v *UEContextReleaseCompleteIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextReleaseCompleteIEValueFieldRowENBUES1APID(v *UEContextReleaseCompleteIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextReleaseCompleteIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(v *UEContextReleaseCompleteIEValue) **s33.InformationOnRecommendedCellsAndENBsForPaging {
	return &v.rowInformationOnRecommendedCellsAndENBsForPaging
}
func BridgeUEContextReleaseCompleteIEValueFieldRowMMEUES1APID(v *UEContextReleaseCompleteIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextReleaseCompleteIEValueFieldRowSecondaryRATDataUsageReportList(v *UEContextReleaseCompleteIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeUEContextReleaseCompleteIEValueFieldRowTimeSinceSecondaryNodeRelease(v *UEContextReleaseCompleteIEValue) **s00.TimeSinceSecondaryNodeRelease {
	return &v.rowTimeSinceSecondaryNodeRelease
}
func BridgeUEContextReleaseCompleteIEValueFieldRowUserLocationInformation(v *UEContextReleaseCompleteIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeUEContextReleaseCompleteIEValueMethodCaptureSemantics(v UEContextReleaseCompleteIEValue, a0 aper.SemanticCapture) UEContextReleaseCompleteIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextReleaseCompleteIEValueMethodCompareSemantics(v UEContextReleaseCompleteIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextReleaseCompleteIEValueMethodDecode(v UEContextReleaseCompleteIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextReleaseCompleteIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextReleaseCompleteIEValueMethodEncode(v UEContextReleaseCompleteIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh(v UEContextReleaseCompleteIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextReleaseCompleteIEValueMethodMatchesID(v UEContextReleaseCompleteIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextReleaseCompleteIEValueMethodReason(v UEContextReleaseCompleteIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextReleaseCompleteIEValueMethodRule(v UEContextReleaseCompleteIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCompleteIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCompleteIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCompleteIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldCodec(v *UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) *s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldGet(v *UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s33.InformationOnRecommendedCellsAndENBsForPaging, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInfo(v *UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInject(v *UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding) *func(s33.InformationOnRecommendedCellsAndENBsForPaging) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldCodec(v *UEContextReleaseCompleteMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldGet(v *UEContextReleaseCompleteMMEUES1APIDIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldInfo(v *UEContextReleaseCompleteMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldInject(v *UEContextReleaseCompleteMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldCodec(v *UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldGet(v *UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldInfo(v *UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldInject(v *UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(v *UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) *s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldGet(v *UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(v *UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldInject(v *UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding) *func(s00.TimeSinceSecondaryNodeRelease) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteUserLocationInformationIEBindingFieldCodec(v *UEContextReleaseCompleteUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCompleteUserLocationInformationIEBindingFieldGet(v *UEContextReleaseCompleteUserLocationInformationIEBinding) *func(*UEContextReleaseCompleteIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeUEContextReleaseCompleteUserLocationInformationIEBindingFieldInfo(v *UEContextReleaseCompleteUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteUserLocationInformationIEBindingFieldInject(v *UEContextReleaseCompleteUserLocationInformationIEBinding) *func(s44.UserLocationInformation) UEContextReleaseCompleteIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldCodec(v *UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) *s17.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldGet(v *UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) *func(*UEContextSuspendRequestIEValue) (*s17.CellIdentifierAndCELevelForCECapableUEs, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInfo(v *UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInject(v *UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding) *func(s17.CellIdentifierAndCELevelForCECapableUEs) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldCodec(v *UEContextSuspendRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldGet(v *UEContextSuspendRequestENBUES1APIDIEBinding) *func(*UEContextSuspendRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldInfo(v *UEContextSuspendRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldInject(v *UEContextSuspendRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestIEContainerAPERValueFieldContext(v *UEContextSuspendRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEContainerAPERValueFieldReceived(v *UEContextSuspendRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEContainerAPERValueFieldReplay(v *UEContextSuspendRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEContainerAPERValueFieldWithoutReplay(v *UEContextSuspendRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldCapture(v *UEContextSuspendRequestIEContainerValueCodec) *func(UEContextSuspendRequestIEContainer, aper.DecodeState) (UEContextSuspendRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldCompare(v *UEContextSuspendRequestIEContainerValueCodec) *func(UEContextSuspendRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldContext(v *UEContextSuspendRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(v *UEContextSuspendRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequestIEContainer, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(v *UEContextSuspendRequestIEContainerValueCodec) *func(UEContextSuspendRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestIEContainerValueCodecFieldPath(v *UEContextSuspendRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestIEContainerValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestIEContainerValueCodec, a0 UEContextSuspendRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestIEContainerValueCodecMethodEncodeChanged(v UEContextSuspendRequestIEContainerValueCodec, a0 UEContextSuspendRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestIEFieldAPERValueFieldContext(v *UEContextSuspendRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEFieldAPERValueFieldReceived(v *UEContextSuspendRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEFieldAPERValueFieldReplay(v *UEContextSuspendRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEFieldAPERValueFieldWithoutReplay(v *UEContextSuspendRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEFieldFieldReceived(v *UEContextSuspendRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextSuspendRequestIEFieldFieldReplay(v *UEContextSuspendRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEFieldFieldStream(v *UEContextSuspendRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextSuspendRequestIEFieldFieldWithoutReplay(v *UEContextSuspendRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(v *UEContextSuspendRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(v *UEContextSuspendRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldCapture(v *UEContextSuspendRequestIEFieldValueCodec) *func(UEContextSuspendRequestIEField, aper.DecodeState) (UEContextSuspendRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldCompare(v *UEContextSuspendRequestIEFieldValueCodec) *func(UEContextSuspendRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldContext(v *UEContextSuspendRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldDecode(v *UEContextSuspendRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequestIEField, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldEncode(v *UEContextSuspendRequestIEFieldValueCodec) *func(UEContextSuspendRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestIEFieldValueCodecFieldPath(v *UEContextSuspendRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestIEFieldValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestIEFieldValueCodec, a0 UEContextSuspendRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestIEFieldValueCodecMethodEncodeChanged(v UEContextSuspendRequestIEFieldValueCodec, a0 UEContextSuspendRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListAPERValueFieldContext(v *UEContextSuspendRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextSuspendRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextSuspendRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldContext(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldPath(v *UEContextSuspendRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestIEValueERABIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendRequestIEValueERABIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestIEValueFieldId(v *UEContextSuspendRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextSuspendRequestIEValueFieldIsOpaque(v *UEContextSuspendRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextSuspendRequestIEValueFieldOpaque(v *UEContextSuspendRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextSuspendRequestIEValueFieldReceived(v *UEContextSuspendRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEValueFieldReplay(v *UEContextSuspendRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(v *UEContextSuspendRequestIEValue) **s17.CellIdentifierAndCELevelForCECapableUEs {
	return &v.rowCellIdentifierAndCELevelForCECapableUEs
}
func BridgeUEContextSuspendRequestIEValueFieldRowENBUES1APID(v *UEContextSuspendRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextSuspendRequestIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(v *UEContextSuspendRequestIEValue) **s33.InformationOnRecommendedCellsAndENBsForPaging {
	return &v.rowInformationOnRecommendedCellsAndENBsForPaging
}
func BridgeUEContextSuspendRequestIEValueFieldRowMMEUES1APID(v *UEContextSuspendRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextSuspendRequestIEValueFieldRowSecondaryRATDataUsageReportList(v *UEContextSuspendRequestIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeUEContextSuspendRequestIEValueFieldRowTimeSinceSecondaryNodeRelease(v *UEContextSuspendRequestIEValue) **s00.TimeSinceSecondaryNodeRelease {
	return &v.rowTimeSinceSecondaryNodeRelease
}
func BridgeUEContextSuspendRequestIEValueFieldRowUserLocationInformation(v *UEContextSuspendRequestIEValue) **s44.UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeUEContextSuspendRequestIEValueMethodCaptureSemantics(v UEContextSuspendRequestIEValue, a0 aper.SemanticCapture) UEContextSuspendRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextSuspendRequestIEValueMethodCompareSemantics(v UEContextSuspendRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextSuspendRequestIEValueMethodDecode(v UEContextSuspendRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextSuspendRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextSuspendRequestIEValueMethodEncode(v UEContextSuspendRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextSuspendRequestIEValueMethodEncodeFresh(v UEContextSuspendRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextSuspendRequestIEValueMethodMatchesID(v UEContextSuspendRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextSuspendRequestIEValueMethodReason(v UEContextSuspendRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextSuspendRequestIEValueMethodRule(v UEContextSuspendRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextSuspendRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldCodec(v *UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) *s33.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldGet(v *UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) *func(*UEContextSuspendRequestIEValue) (*s33.InformationOnRecommendedCellsAndENBsForPaging, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInfo(v *UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInject(v *UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding) *func(s33.InformationOnRecommendedCellsAndENBsForPaging) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldCodec(v *UEContextSuspendRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldGet(v *UEContextSuspendRequestMMEUES1APIDIEBinding) *func(*UEContextSuspendRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldInfo(v *UEContextSuspendRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldInject(v *UEContextSuspendRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldCodec(v *UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldGet(v *UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) *func(*UEContextSuspendRequestIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldInfo(v *UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldInject(v *UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(v *UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) *s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldGet(v *UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) *func(*UEContextSuspendRequestIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(v *UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldInject(v *UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding) *func(s00.TimeSinceSecondaryNodeRelease) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestUserLocationInformationIEBindingFieldCodec(v *UEContextSuspendRequestUserLocationInformationIEBinding) *UserLocationInformationValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendRequestUserLocationInformationIEBindingFieldGet(v *UEContextSuspendRequestUserLocationInformationIEBinding) *func(*UEContextSuspendRequestIEValue) (*s44.UserLocationInformation, bool) {
	return &v.get
}
func BridgeUEContextSuspendRequestUserLocationInformationIEBindingFieldInfo(v *UEContextSuspendRequestUserLocationInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestUserLocationInformationIEBindingFieldInject(v *UEContextSuspendRequestUserLocationInformationIEBinding) *func(s44.UserLocationInformation) UEContextSuspendRequestIEValue {
	return &v.inject
}
func BridgeUserLocationInformationAPERValueFieldContext(v *UserLocationInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationAPERValueFieldReceived(v *UserLocationInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUserLocationInformationAPERValueFieldReplay(v *UserLocationInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationAPERValueFieldWithoutReplay(v *UserLocationInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationValueCodecFieldCapture(v *UserLocationInformationValueCodec) *func(s44.UserLocationInformation, aper.DecodeState) (s44.UserLocationInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeUserLocationInformationValueCodecFieldCompare(v *UserLocationInformationValueCodec) *func(s44.UserLocationInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUserLocationInformationValueCodecFieldContext(v *UserLocationInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationValueCodecFieldDecode(v *UserLocationInformationValueCodec) *func([]byte, aper.DecodeState) (s44.UserLocationInformation, error) {
	return &v.decode
}
func BridgeUserLocationInformationValueCodecFieldEncode(v *UserLocationInformationValueCodec) *func(s44.UserLocationInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUserLocationInformationValueCodecFieldPath(v *UserLocationInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationValueCodecMethodEncodeBudgetValue(v UserLocationInformationValueCodec, a0 s44.UserLocationInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUserLocationInformationValueCodecMethodEncodeChanged(v UserLocationInformationValueCodec, a0 s44.UserLocationInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABModifyResponseIEValue) Selected() (any, bool) {
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
	case 31:
		if value, ok := v.AsERABModifyListBearerModRes(); ok {
			return value, true
		}
	case 32:
		if value, ok := v.AsERABFailedToModifyList(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABReleaseIndicationIEValue) Selected() (any, bool) {
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
	case 110:
		if value, ok := v.AsERABReleasedList(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABReleaseResponseIEValue) Selected() (any, bool) {
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
	case 69:
		if value, ok := v.AsERABReleaseListBearerRelComp(); ok {
			return value, true
		}
	case 34:
		if value, ok := v.AsERABFailedToReleaseList(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABSetupResponseIEValue) Selected() (any, bool) {
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
	case 28:
		if value, ok := v.AsERABSetupListBearerSURes(); ok {
			return value, true
		}
	case 29:
		if value, ok := v.AsERABFailedToSetupListBearerSURes(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *SecondaryRATDataUsageReportIEValue) Selected() (any, bool) {
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
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	case 266:
		if value, ok := v.AsHandoverFlag(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	case 297:
		if value, ok := v.AsTimeSinceSecondaryNodeRelease(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UEContextReleaseCompleteIEValue) Selected() (any, bool) {
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
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	case 213:
		if value, ok := v.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
			return value, true
		}
	case 212:
		if value, ok := v.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	case 297:
		if value, ok := v.AsTimeSinceSecondaryNodeRelease(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UEContextSuspendRequestIEValue) Selected() (any, bool) {
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
	case 213:
		if value, ok := v.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
			return value, true
		}
	case 212:
		if value, ok := v.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	case 297:
		if value, ok := v.AsTimeSinceSecondaryNodeRelease(); ok {
			return value, true
		}
	}
	return nil, false
}
