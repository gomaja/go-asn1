// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s23 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s23

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// PathSwitchRequestFailureIEContainer is the concrete ProtocolIEContainer[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEContainer []PathSwitchRequestFailureIEField

// PathSwitchRequestFailureIEField is the concrete ProtocolIEField[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PathSwitchRequestFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEField) WithoutReplay() PathSwitchRequestFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PathSwitchRequestFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PathSwitchRequestFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *PathSwitchRequestFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestFailureIEField{}
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
	var zero PathSwitchRequestFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// S1SetupFailureIEContainer is the concrete ProtocolIEContainer[S1SetupFailureIEValue].
type S1SetupFailureIEContainer []S1SetupFailureIEField

// S1SetupFailureIEField is the concrete ProtocolIEField[S1SetupFailureIEValue].
type S1SetupFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1SetupFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEField) WithoutReplay() S1SetupFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1SetupFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1SetupFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *S1SetupFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupFailureIEField{}
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
	var zero S1SetupFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UEContextModificationResponseIEContainer is the concrete ProtocolIEContainer[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEContainer []UEContextModificationResponseIEField

// UEContextModificationResponseIEField is the concrete ProtocolIEField[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEField) WithoutReplay() UEContextModificationResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *UEContextModificationResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationResponseIEField{}
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
	var zero UEContextModificationResponseIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UEContextModificationFailureIEContainer is the concrete ProtocolIEContainer[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEContainer []UEContextModificationFailureIEField

// UEContextModificationFailureIEField is the concrete ProtocolIEField[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEField) WithoutReplay() UEContextModificationFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *UEContextModificationFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationFailureIEField{}
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
	var zero UEContextModificationFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MMEConfigurationUpdateFailureIEContainer is the concrete ProtocolIEContainer[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEContainer []MMEConfigurationUpdateFailureIEField

// MMEConfigurationUpdateFailureIEField is the concrete ProtocolIEField[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEConfigurationUpdateFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEField) WithoutReplay() MMEConfigurationUpdateFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEConfigurationUpdateFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEConfigurationUpdateFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *MMEConfigurationUpdateFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateFailureIEField{}
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
	var zero MMEConfigurationUpdateFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UEContextModificationConfirmIEContainer is the concrete ProtocolIEContainer[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEContainer []UEContextModificationConfirmIEField

// UEContextModificationConfirmIEField is the concrete ProtocolIEField[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationConfirmIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEField) WithoutReplay() UEContextModificationConfirmIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationConfirmIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationConfirmIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *UEContextModificationConfirmIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationConfirmIEField{}
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
	var zero UEContextModificationConfirmIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UEContextResumeFailureIEContainer is the concrete ProtocolIEContainer[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEContainer []UEContextResumeFailureIEField

// UEContextResumeFailureIEField is the concrete ProtocolIEField[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextResumeFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEField) WithoutReplay() UEContextResumeFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextResumeFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextResumeFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *UEContextResumeFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeFailureIEField{}
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
	var zero UEContextResumeFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UERadioCapabilityIDMappingResponseIEContainer is the concrete ProtocolIEContainer[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEContainer []UERadioCapabilityIDMappingResponseIEField

// UERadioCapabilityIDMappingResponseIEField is the concrete ProtocolIEField[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UERadioCapabilityIDMappingResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEField) WithoutReplay() UERadioCapabilityIDMappingResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UERadioCapabilityIDMappingResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UERadioCapabilityIDMappingResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *UERadioCapabilityIDMappingResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingResponseIEField{}
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
	var zero UERadioCapabilityIDMappingResponseIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// S1RemovalResponseIEContainer is the concrete ProtocolIEContainer[S1RemovalResponseIEValue].
type S1RemovalResponseIEContainer []S1RemovalResponseIEField

// S1RemovalResponseIEField is the concrete ProtocolIEField[S1RemovalResponseIEValue].
type S1RemovalResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1RemovalResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEField) WithoutReplay() S1RemovalResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1RemovalResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1RemovalResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *S1RemovalResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1RemovalResponseIEField{}
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
	var zero S1RemovalResponseIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// S1RemovalFailureIEContainer is the concrete ProtocolIEContainer[S1RemovalFailureIEValue].
type S1RemovalFailureIEContainer []S1RemovalFailureIEField

// S1RemovalFailureIEField is the concrete ProtocolIEField[S1RemovalFailureIEValue].
type S1RemovalFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1RemovalFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEField) WithoutReplay() S1RemovalFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1RemovalFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1RemovalFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
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
func (v *S1RemovalFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1RemovalFailureIEField{}
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
	var zero S1RemovalFailureIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MMEConfigurationUpdateFailureCauseIEBinding is the concrete IEBinding[Cause, MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) MMEConfigurationUpdateFailureIEValue

	get func(*MMEConfigurationUpdateFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateFailureCauseIEBinding) New(value s14.Cause,

) (MMEConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Get(field *MMEConfigurationUpdateFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateFailureTimeToWaitIEBinding is the concrete IEBinding[TimeToWait, MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureTimeToWaitIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeToWaitValueCodec
	inject func(s00.TimeToWait,

	) MMEConfigurationUpdateFailureIEValue

	get func(*MMEConfigurationUpdateFailureIEValue,

	) (*s00.TimeToWait,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureTimeToWaitIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureTimeToWaitIEBinding) Codec() s02.TimeToWaitValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateFailureTimeToWaitIEBinding) New(value s00.TimeToWait,

) (MMEConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeToWaitValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateFailureTimeToWaitIEBinding) Get(field *MMEConfigurationUpdateFailureIEField) (*s00.TimeToWait,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) MMEConfigurationUpdateFailureIEValue

	get func(*MMEConfigurationUpdateFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (MMEConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Get(field *MMEConfigurationUpdateFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) PathSwitchRequestFailureIEValue

	get func(*PathSwitchRequestFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (PathSwitchRequestFailureIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestFailureMMEUES1APIDIEBinding) Get(field *PathSwitchRequestFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestFailureENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) PathSwitchRequestFailureIEValue

	get func(*PathSwitchRequestFailureIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestFailureENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (PathSwitchRequestFailureIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestFailureENBUES1APIDIEBinding) Get(field *PathSwitchRequestFailureIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestFailureCauseIEBinding is the concrete IEBinding[Cause, PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) PathSwitchRequestFailureIEValue

	get func(*PathSwitchRequestFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestFailureCauseIEBinding) New(value s14.Cause,

) (PathSwitchRequestFailureIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestFailureCauseIEBinding) Get(field *PathSwitchRequestFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) PathSwitchRequestFailureIEValue

	get func(*PathSwitchRequestFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (PathSwitchRequestFailureIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) Get(field *PathSwitchRequestFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalFailureCauseIEBinding is the concrete IEBinding[Cause, S1RemovalFailureIEValue].
type S1RemovalFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) S1RemovalFailureIEValue

	get func(*S1RemovalFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1RemovalFailureCauseIEBinding) New(value s14.Cause,

) (S1RemovalFailureIEField, error) {
	if b.inject == nil {
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalFailureCauseIEBinding) Get(field *S1RemovalFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, S1RemovalFailureIEValue].
type S1RemovalFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) S1RemovalFailureIEValue

	get func(*S1RemovalFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1RemovalFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (S1RemovalFailureIEField, error) {
	if b.inject == nil {
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalFailureCriticalityDiagnosticsIEBinding) Get(field *S1RemovalFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalResponseMMEnameIEBinding is the concrete IEBinding[MMEname, S1RemovalResponseIEValue].
type S1RemovalResponseMMEnameIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEnameValueCodec
	inject func(s00.MMEname,

	) S1RemovalResponseIEValue

	get func(*S1RemovalResponseIEValue,

	) (*s00.MMEname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalResponseMMEnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalResponseMMEnameIEBinding) Codec() s01.MMEnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1RemovalResponseMMEnameIEBinding) New(value s00.MMEname,

) (S1RemovalResponseIEField, error) {
	if b.inject == nil {
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalResponseMMEnameIEBinding) Get(field *S1RemovalResponseIEField) (*s00.MMEname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, S1RemovalResponseIEValue].
type S1RemovalResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) S1RemovalResponseIEValue

	get func(*S1RemovalResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1RemovalResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (S1RemovalResponseIEField, error) {
	if b.inject == nil {
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalResponseCriticalityDiagnosticsIEBinding) Get(field *S1RemovalResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupFailureCauseIEBinding is the concrete IEBinding[Cause, S1SetupFailureIEValue].
type S1SetupFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) S1SetupFailureIEValue

	get func(*S1SetupFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupFailureCauseIEBinding) New(value s14.Cause,

) (S1SetupFailureIEField, error) {
	if b.inject == nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupFailureCauseIEBinding) Get(field *S1SetupFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupFailureTimeToWaitIEBinding is the concrete IEBinding[TimeToWait, S1SetupFailureIEValue].
type S1SetupFailureTimeToWaitIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeToWaitValueCodec
	inject func(s00.TimeToWait,

	) S1SetupFailureIEValue

	get func(*S1SetupFailureIEValue,

	) (*s00.TimeToWait,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureTimeToWaitIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureTimeToWaitIEBinding) Codec() s02.TimeToWaitValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupFailureTimeToWaitIEBinding) New(value s00.TimeToWait,

) (S1SetupFailureIEField, error) {
	if b.inject == nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeToWaitValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupFailureTimeToWaitIEBinding) Get(field *S1SetupFailureIEField) (*s00.TimeToWait,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, S1SetupFailureIEValue].
type S1SetupFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) S1SetupFailureIEValue

	get func(*S1SetupFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (S1SetupFailureIEField, error) {
	if b.inject == nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupFailureCriticalityDiagnosticsIEBinding) Get(field *S1SetupFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationConfirmMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextModificationConfirmIEValue].
type UEContextModificationConfirmMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationConfirmIEValue

	get func(*UEContextModificationConfirmIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationConfirmMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationConfirmIEField, error) {
	if b.inject == nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationConfirmMMEUES1APIDIEBinding) Get(field *UEContextModificationConfirmIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationConfirmENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextModificationConfirmIEValue].
type UEContextModificationConfirmENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationConfirmIEValue

	get func(*UEContextModificationConfirmIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationConfirmENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationConfirmIEField, error) {
	if b.inject == nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationConfirmENBUES1APIDIEBinding) Get(field *UEContextModificationConfirmIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationConfirmCSGMembershipStatusIEBinding is the concrete IEBinding[CSGMembershipStatus, UEContextModificationConfirmIEValue].
type UEContextModificationConfirmCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) UEContextModificationConfirmIEValue

	get func(*UEContextModificationConfirmIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmCSGMembershipStatusIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationConfirmCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (UEContextModificationConfirmIEField, error) {
	if b.inject == nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationConfirmCSGMembershipStatusIEBinding) Get(field *UEContextModificationConfirmIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationConfirmCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UEContextModificationConfirmIEValue].
type UEContextModificationConfirmCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextModificationConfirmIEValue

	get func(*UEContextModificationConfirmIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationConfirmCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextModificationConfirmIEField, error) {
	if b.inject == nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationConfirmCriticalityDiagnosticsIEBinding) Get(field *UEContextModificationConfirmIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextModificationFailureIEValue].
type UEContextModificationFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationFailureIEValue

	get func(*UEContextModificationFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationFailureIEField, error) {
	if b.inject == nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationFailureMMEUES1APIDIEBinding) Get(field *UEContextModificationFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationFailureENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextModificationFailureIEValue].
type UEContextModificationFailureENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationFailureIEValue

	get func(*UEContextModificationFailureIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationFailureENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationFailureIEField, error) {
	if b.inject == nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationFailureENBUES1APIDIEBinding) Get(field *UEContextModificationFailureIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationFailureCauseIEBinding is the concrete IEBinding[Cause, UEContextModificationFailureIEValue].
type UEContextModificationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) UEContextModificationFailureIEValue

	get func(*UEContextModificationFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextModificationFailureCauseIEBinding) New(value s14.Cause,

) (UEContextModificationFailureIEField, error) {
	if b.inject == nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationFailureCauseIEBinding) Get(field *UEContextModificationFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UEContextModificationFailureIEValue].
type UEContextModificationFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextModificationFailureIEValue

	get func(*UEContextModificationFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextModificationFailureIEField, error) {
	if b.inject == nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationFailureCriticalityDiagnosticsIEBinding) Get(field *UEContextModificationFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationResponseMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextModificationResponseIEValue].
type UEContextModificationResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationResponseIEValue

	get func(*UEContextModificationResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationResponseIEField, error) {
	if b.inject == nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationResponseMMEUES1APIDIEBinding) Get(field *UEContextModificationResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationResponseENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextModificationResponseIEValue].
type UEContextModificationResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationResponseIEValue

	get func(*UEContextModificationResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationResponseIEField, error) {
	if b.inject == nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationResponseENBUES1APIDIEBinding) Get(field *UEContextModificationResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UEContextModificationResponseIEValue].
type UEContextModificationResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextModificationResponseIEValue

	get func(*UEContextModificationResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextModificationResponseIEField, error) {
	if b.inject == nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationResponseCriticalityDiagnosticsIEBinding) Get(field *UEContextModificationResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextResumeFailureIEValue].
type UEContextResumeFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextResumeFailureIEValue

	get func(*UEContextResumeFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextResumeFailureIEField, error) {
	if b.inject == nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Get(field *UEContextResumeFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeFailureENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextResumeFailureIEValue].
type UEContextResumeFailureENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextResumeFailureIEValue

	get func(*UEContextResumeFailureIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeFailureENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextResumeFailureIEField, error) {
	if b.inject == nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeFailureENBUES1APIDIEBinding) Get(field *UEContextResumeFailureIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeFailureCauseIEBinding is the concrete IEBinding[Cause, UEContextResumeFailureIEValue].
type UEContextResumeFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) UEContextResumeFailureIEValue

	get func(*UEContextResumeFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextResumeFailureCauseIEBinding) New(value s14.Cause,

) (UEContextResumeFailureIEField, error) {
	if b.inject == nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeFailureCauseIEBinding) Get(field *UEContextResumeFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UEContextResumeFailureIEValue].
type UEContextResumeFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextResumeFailureIEValue

	get func(*UEContextResumeFailureIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeFailureCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextResumeFailureIEField, error) {
	if b.inject == nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeFailureCriticalityDiagnosticsIEBinding) Get(field *UEContextResumeFailureIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UERadioCapabilityIDMappingResponseIEValue

	get func(*UERadioCapabilityIDMappingResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Get(field *UERadioCapabilityIDMappingResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueERABIEContainerList, error)
	encode  func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) New(value MMEConfigurationUpdateFailureIEValueERABIEContainerList) (MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueERABIEContainerList []MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer

// PathSwitchRequestFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueERABIEContainerList, error)
	encode  func(PathSwitchRequestFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailureIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) New(value PathSwitchRequestFailureIEValueERABIEContainerList) (PathSwitchRequestFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) encodeChanged(value PathSwitchRequestFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueERABIEContainerList []PathSwitchRequestFailureIEValueProtocolIESingleContainer

// S1RemovalFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalFailureIEValueERABIEContainerList, error)
	encode  func(S1RemovalFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalFailureIEValueERABIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1RemovalFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalFailureIEValueERABIEContainerListValueCodec) New(value S1RemovalFailureIEValueERABIEContainerList) (S1RemovalFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value S1RemovalFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1RemovalFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalFailureIEValueERABIEContainerListValueCodec) encodeChanged(value S1RemovalFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[S1RemovalFailureIEValue].
type S1RemovalFailureIEValueERABIEContainerList []S1RemovalFailureIEValueProtocolIESingleContainer

// S1RemovalResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalResponseIEValueERABIEContainerList, error)
	encode  func(S1RemovalResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalResponseIEValueERABIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1RemovalResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalResponseIEValueERABIEContainerListValueCodec) New(value S1RemovalResponseIEValueERABIEContainerList) (S1RemovalResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value S1RemovalResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1RemovalResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalResponseIEValueERABIEContainerListValueCodec) encodeChanged(value S1RemovalResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalResponseIEValueERABIEContainerList is the concrete ERABIEContainerList[S1RemovalResponseIEValue].
type S1RemovalResponseIEValueERABIEContainerList []S1RemovalResponseIEValueProtocolIESingleContainer

// S1SetupFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupFailureIEValueERABIEContainerList, error)
	encode  func(S1SetupFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupFailureIEValueERABIEContainerList, aper.DecodeState) (S1SetupFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1SetupFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupFailureIEValueERABIEContainerListValueCodec) New(value S1SetupFailureIEValueERABIEContainerList) (S1SetupFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value S1SetupFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1SetupFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1SetupFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupFailureIEValueERABIEContainerListValueCodec) encodeChanged(value S1SetupFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[S1SetupFailureIEValue].
type S1SetupFailureIEValueERABIEContainerList []S1SetupFailureIEValueProtocolIESingleContainer

// UEContextModificationConfirmIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueERABIEContainerList, error)
	encode  func(UEContextModificationConfirmIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirmIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmIEValueERABIEContainerListValueCodec) New(value UEContextModificationConfirmIEValueERABIEContainerList) (UEContextModificationConfirmIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationConfirmIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationConfirmIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationConfirmIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationConfirmIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueERABIEContainerList []UEContextModificationConfirmIEValueProtocolIESingleContainer

// UEContextModificationFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueERABIEContainerList, error)
	encode  func(UEContextModificationFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailureIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureIEValueERABIEContainerListValueCodec) New(value UEContextModificationFailureIEValueERABIEContainerList) (UEContextModificationFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEValueERABIEContainerList []UEContextModificationFailureIEValueProtocolIESingleContainer

// UEContextModificationResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueERABIEContainerList, error)
	encode  func(UEContextModificationResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseIEValueERABIEContainerListValueCodec) New(value UEContextModificationResponseIEValueERABIEContainerList) (UEContextModificationResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueERABIEContainerList []UEContextModificationResponseIEValueProtocolIESingleContainer

// UEContextResumeFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueERABIEContainerList, error)
	encode  func(UEContextResumeFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailureIEValueERABIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEValueERABIEContainerListValueCodec) New(value UEContextResumeFailureIEValueERABIEContainerList) (UEContextResumeFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextResumeFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextResumeFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueERABIEContainerList []UEContextResumeFailureIEValueProtocolIESingleContainer

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error)
	encode  func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) New(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerList is the concrete ERABIEContainerList[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// MMEConfigurationUpdateFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEField, error)
	encode  func(MMEConfigurationUpdateFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailureIEField, aper.DecodeState) (MMEConfigurationUpdateFailureIEField, aper.Snapshot)
	compare func(MMEConfigurationUpdateFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureIEFieldValueCodec) New(value MMEConfigurationUpdateFailureIEField) (MMEConfigurationUpdateFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureIEFieldValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateFailureIEFieldValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureIEFieldValueCodec) encodeChanged(value MMEConfigurationUpdateFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEField, error)
	encode  func(PathSwitchRequestFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailureIEField, aper.DecodeState) (PathSwitchRequestFailureIEField, aper.Snapshot)
	compare func(PathSwitchRequestFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureIEFieldValueCodec) New(value PathSwitchRequestFailureIEField) (PathSwitchRequestFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureIEFieldValueCodec) EncodeAPER(value PathSwitchRequestFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestFailureIEFieldValueCodec) encodeBudgetValue(value PathSwitchRequestFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureIEFieldValueCodec) encodeChanged(value PathSwitchRequestFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[S1RemovalFailureIEValue]].
type S1RemovalFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalFailureIEField, error)
	encode  func(S1RemovalFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalFailureIEField, aper.DecodeState) (S1RemovalFailureIEField, aper.Snapshot)
	compare func(S1RemovalFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalFailureIEFieldValueCodec) New(value S1RemovalFailureIEField) (S1RemovalFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1RemovalFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalFailureIEFieldValueCodec) EncodeAPER(value S1RemovalFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalFailureIEFieldValueCodec) encodeBudgetValue(value S1RemovalFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalFailureIEFieldValueCodec) encodeChanged(value S1RemovalFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalResponseIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[S1RemovalResponseIEValue]].
type S1RemovalResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalResponseIEField, error)
	encode  func(S1RemovalResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalResponseIEField, aper.DecodeState) (S1RemovalResponseIEField, aper.Snapshot)
	compare func(S1RemovalResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalResponseIEFieldValueCodec) New(value S1RemovalResponseIEField) (S1RemovalResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1RemovalResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalResponseIEFieldValueCodec) EncodeAPER(value S1RemovalResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalResponseIEFieldValueCodec) encodeBudgetValue(value S1RemovalResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalResponseIEFieldValueCodec) encodeChanged(value S1RemovalResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[S1SetupFailureIEValue]].
type S1SetupFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupFailureIEField, error)
	encode  func(S1SetupFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupFailureIEField, aper.DecodeState) (S1SetupFailureIEField, aper.Snapshot)
	compare func(S1SetupFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupFailureIEFieldValueCodec) New(value S1SetupFailureIEField) (S1SetupFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1SetupFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupFailureIEFieldValueCodec) EncodeAPER(value S1SetupFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1SetupFailureIEFieldValueCodec) encodeBudgetValue(value S1SetupFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupFailureIEFieldValueCodec) encodeChanged(value S1SetupFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirmIEField, error)
	encode  func(UEContextModificationConfirmIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirmIEField, aper.DecodeState) (UEContextModificationConfirmIEField, aper.Snapshot)
	compare func(UEContextModificationConfirmIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmIEFieldValueCodec) New(value UEContextModificationConfirmIEField) (UEContextModificationConfirmIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmIEFieldValueCodec) EncodeAPER(value UEContextModificationConfirmIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationConfirmIEFieldValueCodec) encodeBudgetValue(value UEContextModificationConfirmIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmIEFieldValueCodec) encodeChanged(value UEContextModificationConfirmIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailureIEField, error)
	encode  func(UEContextModificationFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailureIEField, aper.DecodeState) (UEContextModificationFailureIEField, aper.Snapshot)
	compare func(UEContextModificationFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureIEFieldValueCodec) New(value UEContextModificationFailureIEField) (UEContextModificationFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureIEFieldValueCodec) EncodeAPER(value UEContextModificationFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureIEFieldValueCodec) encodeBudgetValue(value UEContextModificationFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureIEFieldValueCodec) encodeChanged(value UEContextModificationFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponseIEField, error)
	encode  func(UEContextModificationResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponseIEField, aper.DecodeState) (UEContextModificationResponseIEField, aper.Snapshot)
	compare func(UEContextModificationResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseIEFieldValueCodec) New(value UEContextModificationResponseIEField) (UEContextModificationResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseIEFieldValueCodec) EncodeAPER(value UEContextModificationResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationResponseIEFieldValueCodec) encodeBudgetValue(value UEContextModificationResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseIEFieldValueCodec) encodeChanged(value UEContextModificationResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailureIEField, error)
	encode  func(UEContextResumeFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailureIEField, aper.DecodeState) (UEContextResumeFailureIEField, aper.Snapshot)
	compare func(UEContextResumeFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEFieldValueCodec) New(value UEContextResumeFailureIEField) (UEContextResumeFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEFieldValueCodec) EncodeAPER(value UEContextResumeFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEFieldValueCodec) encodeBudgetValue(value UEContextResumeFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEFieldValueCodec) encodeChanged(value UEContextResumeFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, error)
	encode  func(UERadioCapabilityIDMappingResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEField, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) New(value UERadioCapabilityIDMappingResponseIEField) (UERadioCapabilityIDMappingResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEContainer, error)
	encode  func(MMEConfigurationUpdateFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailureIEContainer, aper.DecodeState) (MMEConfigurationUpdateFailureIEContainer, aper.Snapshot)
	compare func(MMEConfigurationUpdateFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureIEContainerValueCodec) New(value MMEConfigurationUpdateFailureIEContainer) (MMEConfigurationUpdateFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureIEContainerValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateFailureIEContainerValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureIEContainerValueCodec) encodeChanged(value MMEConfigurationUpdateFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEContainer, error)
	encode  func(PathSwitchRequestFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailureIEContainer, aper.DecodeState) (PathSwitchRequestFailureIEContainer, aper.Snapshot)
	compare func(PathSwitchRequestFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureIEContainerValueCodec) New(value PathSwitchRequestFailureIEContainer) (PathSwitchRequestFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureIEContainerValueCodec) EncodeAPER(value PathSwitchRequestFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestFailureIEContainerValueCodec) encodeBudgetValue(value PathSwitchRequestFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureIEContainerValueCodec) encodeChanged(value PathSwitchRequestFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[S1RemovalFailureIEValue]].
type S1RemovalFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalFailureIEContainer, error)
	encode  func(S1RemovalFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalFailureIEContainer, aper.DecodeState) (S1RemovalFailureIEContainer, aper.Snapshot)
	compare func(S1RemovalFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalFailureIEContainerValueCodec) New(value S1RemovalFailureIEContainer) (S1RemovalFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1RemovalFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalFailureIEContainerValueCodec) EncodeAPER(value S1RemovalFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalFailureIEContainerValueCodec) encodeBudgetValue(value S1RemovalFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalFailureIEContainerValueCodec) encodeChanged(value S1RemovalFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalResponseIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[S1RemovalResponseIEValue]].
type S1RemovalResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalResponseIEContainer, error)
	encode  func(S1RemovalResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalResponseIEContainer, aper.DecodeState) (S1RemovalResponseIEContainer, aper.Snapshot)
	compare func(S1RemovalResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalResponseIEContainerValueCodec) New(value S1RemovalResponseIEContainer) (S1RemovalResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1RemovalResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalResponseIEContainerValueCodec) EncodeAPER(value S1RemovalResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalResponseIEContainerValueCodec) encodeBudgetValue(value S1RemovalResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalResponseIEContainerValueCodec) encodeChanged(value S1RemovalResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[S1SetupFailureIEValue]].
type S1SetupFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupFailureIEContainer, error)
	encode  func(S1SetupFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupFailureIEContainer, aper.DecodeState) (S1SetupFailureIEContainer, aper.Snapshot)
	compare func(S1SetupFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupFailureIEContainerValueCodec) New(value S1SetupFailureIEContainer) (S1SetupFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1SetupFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupFailureIEContainerValueCodec) EncodeAPER(value S1SetupFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1SetupFailureIEContainerValueCodec) encodeBudgetValue(value S1SetupFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupFailureIEContainerValueCodec) encodeChanged(value S1SetupFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirmIEContainer, error)
	encode  func(UEContextModificationConfirmIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirmIEContainer, aper.DecodeState) (UEContextModificationConfirmIEContainer, aper.Snapshot)
	compare func(UEContextModificationConfirmIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmIEContainerValueCodec) New(value UEContextModificationConfirmIEContainer) (UEContextModificationConfirmIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmIEContainerValueCodec) EncodeAPER(value UEContextModificationConfirmIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationConfirmIEContainerValueCodec) encodeBudgetValue(value UEContextModificationConfirmIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmIEContainerValueCodec) encodeChanged(value UEContextModificationConfirmIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailureIEContainer, error)
	encode  func(UEContextModificationFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailureIEContainer, aper.DecodeState) (UEContextModificationFailureIEContainer, aper.Snapshot)
	compare func(UEContextModificationFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureIEContainerValueCodec) New(value UEContextModificationFailureIEContainer) (UEContextModificationFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureIEContainerValueCodec) EncodeAPER(value UEContextModificationFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureIEContainerValueCodec) encodeBudgetValue(value UEContextModificationFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureIEContainerValueCodec) encodeChanged(value UEContextModificationFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponseIEContainer, error)
	encode  func(UEContextModificationResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponseIEContainer, aper.DecodeState) (UEContextModificationResponseIEContainer, aper.Snapshot)
	compare func(UEContextModificationResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseIEContainerValueCodec) New(value UEContextModificationResponseIEContainer) (UEContextModificationResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseIEContainerValueCodec) EncodeAPER(value UEContextModificationResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationResponseIEContainerValueCodec) encodeBudgetValue(value UEContextModificationResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseIEContainerValueCodec) encodeChanged(value UEContextModificationResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailureIEContainer, error)
	encode  func(UEContextResumeFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailureIEContainer, aper.DecodeState) (UEContextResumeFailureIEContainer, aper.Snapshot)
	compare func(UEContextResumeFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEContainerValueCodec) New(value UEContextResumeFailureIEContainer) (UEContextResumeFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEContainerValueCodec) EncodeAPER(value UEContextResumeFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEContainerValueCodec) encodeBudgetValue(value UEContextResumeFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEContainerValueCodec) encodeChanged(value UEContextResumeFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, error)
	encode  func(UERadioCapabilityIDMappingResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEContainer, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) New(value UERadioCapabilityIDMappingResponseIEContainer) (UERadioCapabilityIDMappingResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) New(value MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList []MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer

// PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) New(value PathSwitchRequestFailureIEValueProtocolErrorIEContainerList) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueProtocolErrorIEContainerList []PathSwitchRequestFailureIEValueProtocolIESingleContainer

// S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(S1RemovalFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) New(value S1RemovalFailureIEValueProtocolErrorIEContainerList) (S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1RemovalFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1RemovalFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[S1RemovalFailureIEValue].
type S1RemovalFailureIEValueProtocolErrorIEContainerList []S1RemovalFailureIEValueProtocolIESingleContainer

// S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(S1RemovalResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) New(value S1RemovalResponseIEValueProtocolErrorIEContainerList) (S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1RemovalResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1RemovalResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalResponseIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[S1RemovalResponseIEValue].
type S1RemovalResponseIEValueProtocolErrorIEContainerList []S1RemovalResponseIEValueProtocolIESingleContainer

// S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(S1SetupFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1SetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) New(value S1SetupFailureIEValueProtocolErrorIEContainerList) (S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1SetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1SetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[S1SetupFailureIEValue].
type S1SetupFailureIEValueProtocolErrorIEContainerList []S1SetupFailureIEValueProtocolIESingleContainer

// UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationConfirmIEValueProtocolErrorIEContainerList) (UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueProtocolErrorIEContainerList []UEContextModificationConfirmIEValueProtocolIESingleContainer

// UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationFailureIEValueProtocolErrorIEContainerList) (UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEValueProtocolErrorIEContainerList []UEContextModificationFailureIEValueProtocolIESingleContainer

// UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationResponseIEValueProtocolErrorIEContainerList) (UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueProtocolErrorIEContainerList []UEContextModificationResponseIEValueProtocolIESingleContainer

// UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextResumeFailureIEValueProtocolErrorIEContainerList) (UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextResumeFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolErrorIEContainerList []UEContextResumeFailureIEValueProtocolIESingleContainer

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, error)
	encode  func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) New(value MMEConfigurationUpdateFailureIEValueProtocolIEContainerList) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueProtocolIEContainerList []MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer

// PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolIEContainerList, error)
	encode  func(PathSwitchRequestFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) New(value PathSwitchRequestFailureIEValueProtocolIEContainerList) (PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value PathSwitchRequestFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueProtocolIEContainerList []PathSwitchRequestFailureIEValueProtocolIESingleContainer

// S1RemovalFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalFailureIEValueProtocolIEContainerList, error)
	encode  func(S1RemovalFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalFailureIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1RemovalFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalFailureIEValueProtocolIEContainerListValueCodec) New(value S1RemovalFailureIEValueProtocolIEContainerList) (S1RemovalFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1RemovalFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1RemovalFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1RemovalFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[S1RemovalFailureIEValue].
type S1RemovalFailureIEValueProtocolIEContainerList []S1RemovalFailureIEValueProtocolIESingleContainer

// S1RemovalResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalResponseIEValueProtocolIEContainerList, error)
	encode  func(S1RemovalResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalResponseIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1RemovalResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalResponseIEValueProtocolIEContainerListValueCodec) New(value S1RemovalResponseIEValueProtocolIEContainerList) (S1RemovalResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1RemovalResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1RemovalResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1RemovalResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalResponseIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[S1RemovalResponseIEValue].
type S1RemovalResponseIEValueProtocolIEContainerList []S1RemovalResponseIEValueProtocolIESingleContainer

// S1SetupFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupFailureIEValueProtocolIEContainerList, error)
	encode  func(S1SetupFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupFailureIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1SetupFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupFailureIEValueProtocolIEContainerListValueCodec) New(value S1SetupFailureIEValueProtocolIEContainerList) (S1SetupFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1SetupFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1SetupFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1SetupFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1SetupFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[S1SetupFailureIEValue].
type S1SetupFailureIEValueProtocolIEContainerList []S1SetupFailureIEValueProtocolIESingleContainer

// UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationConfirmIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirmIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationConfirmIEValueProtocolIEContainerList) (UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueProtocolIEContainerList []UEContextModificationConfirmIEValueProtocolIESingleContainer

// UEContextModificationFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailureIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationFailureIEValueProtocolIEContainerList) (UEContextModificationFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEValueProtocolIEContainerList []UEContextModificationFailureIEValueProtocolIESingleContainer

// UEContextModificationResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationResponseIEValueProtocolIEContainerList) (UEContextModificationResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueProtocolIEContainerList []UEContextModificationResponseIEValueProtocolIESingleContainer

// UEContextResumeFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueProtocolIEContainerList, error)
	encode  func(UEContextResumeFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailureIEValueProtocolIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) New(value UEContextResumeFailureIEValueProtocolIEContainerList) (UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolIEContainerList []UEContextResumeFailureIEValueProtocolIESingleContainer

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MMEConfigurationUpdateFailureIEValue].
type MMEConfigurationUpdateFailureIEValueProtocolIESingleContainer = MMEConfigurationUpdateFailureIEField

// PathSwitchRequestFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) WithoutReplay() PathSwitchRequestFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[PathSwitchRequestFailureIEValue].
type PathSwitchRequestFailureIEValueProtocolIESingleContainer = PathSwitchRequestFailureIEField

// S1RemovalFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEValueERABIEContainerListAPERValue) WithoutReplay() S1RemovalFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[S1RemovalFailureIEValue].
type S1RemovalFailureIEValueProtocolIESingleContainer = S1RemovalFailureIEField

// S1RemovalResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEValueERABIEContainerListAPERValue) WithoutReplay() S1RemovalResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalResponseIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[S1RemovalResponseIEValue].
type S1RemovalResponseIEValueProtocolIESingleContainer = S1RemovalResponseIEField

// S1SetupFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEValueERABIEContainerListAPERValue) WithoutReplay() S1SetupFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[S1SetupFailureIEValue].
type S1SetupFailureIEValueProtocolIESingleContainer = S1SetupFailureIEField

// UEContextModificationConfirmIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationConfirmIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationConfirmIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueProtocolIESingleContainer = UEContextModificationConfirmIEField

// UEContextModificationFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEValueProtocolIESingleContainer = UEContextModificationFailureIEField

// UEContextModificationResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueProtocolIESingleContainer = UEContextModificationResponseIEField

// UEContextResumeFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextResumeFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolIESingleContainer = UEContextResumeFailureIEField

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer = UERadioCapabilityIDMappingResponseIEField

// MMEConfigurationUpdateFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEFieldAPERValue) WithoutReplay() MMEConfigurationUpdateFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEFieldAPERValue) WithoutReplay() PathSwitchRequestFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[S1RemovalFailureIEValue]].
type S1RemovalFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEFieldAPERValue) WithoutReplay() S1RemovalFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalResponseIEFieldAPERValue is the concrete APERValue[ProtocolIEField[S1RemovalResponseIEValue]].
type S1RemovalResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEFieldAPERValue) WithoutReplay() S1RemovalResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[S1SetupFailureIEValue]].
type S1SetupFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEFieldAPERValue) WithoutReplay() S1SetupFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationConfirmIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEFieldAPERValue) WithoutReplay() UEContextModificationConfirmIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEFieldAPERValue) WithoutReplay() UEContextModificationFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEFieldAPERValue) WithoutReplay() UEContextModificationResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEFieldAPERValue) WithoutReplay() UEContextResumeFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEFieldAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEContainerAPERValue) WithoutReplay() MMEConfigurationUpdateFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEContainerAPERValue) WithoutReplay() PathSwitchRequestFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[S1RemovalFailureIEValue]].
type S1RemovalFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEContainerAPERValue) WithoutReplay() S1RemovalFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalResponseIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[S1RemovalResponseIEValue]].
type S1RemovalResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEContainerAPERValue) WithoutReplay() S1RemovalResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[S1SetupFailureIEValue]].
type S1SetupFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEContainerAPERValue) WithoutReplay() S1SetupFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationConfirmIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEContainerAPERValue) WithoutReplay() UEContextModificationConfirmIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEContainerAPERValue) WithoutReplay() UEContextModificationFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEContainerAPERValue) WithoutReplay() UEContextModificationResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEContainerAPERValue) WithoutReplay() UEContextResumeFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEContainerAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationConfirmIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[MMEConfigurationUpdateFailureIEValue]].
type MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[PathSwitchRequestFailureIEValue]].
type PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[S1RemovalFailureIEValue]].
type S1RemovalFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1RemovalFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[S1RemovalResponseIEValue]].
type S1RemovalResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1RemovalResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[S1SetupFailureIEValue]].
type S1SetupFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1SetupFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextModificationConfirmIEValue]].
type UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationConfirmIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextModificationFailureIEValue]].
type UEContextModificationFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextModificationResponseIEValue]].
type UEContextModificationResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextResumeFailureIEValue]].
type UEContextResumeFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextResumeFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UERadioCapabilityIDMappingResponseIEValue]].
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APMMEConfigurationUpdateFailureIEValue(v *MMEConfigurationUpdateFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s00.BridgeCaptureS1APTimeToWait(v.rowTimeToWait, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateFailureIEValue) captureSemantics(s aper.SemanticCapture) MMEConfigurationUpdateFailureIEValue {
	BridgeCaptureS1APMMEConfigurationUpdateFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEConfigurationUpdateFailureIEValue(v *MMEConfigurationUpdateFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s07.BridgeCompareS1APTimeToWait(v.rowTimeToWait, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEConfigurationUpdateFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APPathSwitchRequestFailureIEValue(v *PathSwitchRequestFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestFailureIEValue) captureSemantics(s aper.SemanticCapture) PathSwitchRequestFailureIEValue {
	BridgeCaptureS1APPathSwitchRequestFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPathSwitchRequestFailureIEValue(v *PathSwitchRequestFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPathSwitchRequestFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1RemovalFailureIEValue(v *S1RemovalFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalFailureIEValue) captureSemantics(s aper.SemanticCapture) S1RemovalFailureIEValue {
	BridgeCaptureS1APS1RemovalFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1RemovalFailureIEValue(v *S1RemovalFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1RemovalFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1RemovalResponseIEValue(v *S1RemovalResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(61):
			{
				f := s.Begin()
				s.Bool(v.rowMMEname == nil)
				if v.rowMMEname != nil {
					s00.BridgeCaptureS1APMMEname(v.rowMMEname, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalResponseIEValue) captureSemantics(s aper.SemanticCapture) S1RemovalResponseIEValue {
	BridgeCaptureS1APS1RemovalResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1RemovalResponseIEValue(v *S1RemovalResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(61):
			{
				f := s.Begin()
				s.Bool(v.rowMMEname == nil)
				if v.rowMMEname != nil {
					s02.BridgeCompareS1APMMEname(v.rowMMEname, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1RemovalResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1SetupFailureIEValue(v *S1SetupFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s00.BridgeCaptureS1APTimeToWait(v.rowTimeToWait, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupFailureIEValue) captureSemantics(s aper.SemanticCapture) S1SetupFailureIEValue {
	BridgeCaptureS1APS1SetupFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1SetupFailureIEValue(v *S1SetupFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s07.BridgeCompareS1APTimeToWait(v.rowTimeToWait, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1SetupFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextModificationConfirmIEValue(v *UEContextModificationConfirmIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationConfirmIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationConfirmIEValue {
	BridgeCaptureS1APUEContextModificationConfirmIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationConfirmIEValue(v *UEContextModificationConfirmIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationConfirmIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationConfirmIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextModificationFailureIEValue(v *UEContextModificationFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationFailureIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationFailureIEValue {
	BridgeCaptureS1APUEContextModificationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationFailureIEValue(v *UEContextModificationFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextModificationResponseIEValue(v *UEContextModificationResponseIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationResponseIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationResponseIEValue {
	BridgeCaptureS1APUEContextModificationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationResponseIEValue(v *UEContextModificationResponseIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextResumeFailureIEValue(v *UEContextResumeFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeFailureIEValue) captureSemantics(s aper.SemanticCapture) UEContextResumeFailureIEValue {
	BridgeCaptureS1APUEContextResumeFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextResumeFailureIEValue(v *UEContextResumeFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextResumeFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUERadioCapabilityIDMappingResponseIEValue(v *UERadioCapabilityIDMappingResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s00.BridgeCaptureS1APUERadioCapability(v.rowUERadioCapability, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingResponseIEValue) captureSemantics(s aper.SemanticCapture) UERadioCapabilityIDMappingResponseIEValue {
	BridgeCaptureS1APUERadioCapabilityIDMappingResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUERadioCapabilityIDMappingResponseIEValue(v *UERadioCapabilityIDMappingResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s07.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUERadioCapabilityIDMappingResponseIEValue(&v, &s)
	return s
}

type MMEConfigurationUpdateFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s14.Cause
	rowTimeToWait             *s00.TimeToWait
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v MMEConfigurationUpdateFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(65):
		return v.rowTimeToWait != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *MMEConfigurationUpdateFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEConfigurationUpdateFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateFailureIEs"}}
}
func (MMEConfigurationUpdateFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(65):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
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
func (v *MMEConfigurationUpdateFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *MMEConfigurationUpdateFailureIEValue) AsTimeToWait() (*s00.TimeToWait, bool) {
	if v == nil || v.id != s00.ProtocolIEID(65) || v.rowTimeToWait == nil {
		return nil, false
	}
	return v.rowTimeToWait, true
}
func (v *MMEConfigurationUpdateFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v MMEConfigurationUpdateFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEConfigurationUpdateFailureIEValue, error) {
	out := MMEConfigurationUpdateFailureIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(65):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeToWait"})
		value := s00.TimeToWait(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeToWait:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeToWait = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v MMEConfigurationUpdateFailureIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v MMEConfigurationUpdateFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(65):
		if v.rowTimeToWait == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateFailureIEs.id-TimeToWait:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeToWait), 6, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEConfigurationUpdateFailureIEValue:", v.id)
	}
}

type PathSwitchRequestFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v PathSwitchRequestFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *PathSwitchRequestFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PathSwitchRequestFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs"}}
}
func (PathSwitchRequestFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *PathSwitchRequestFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *PathSwitchRequestFailureIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *PathSwitchRequestFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *PathSwitchRequestFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v PathSwitchRequestFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PathSwitchRequestFailureIEValue, error) {
	out := PathSwitchRequestFailureIEValue{id: id}
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
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v PathSwitchRequestFailureIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PathSwitchRequestFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestFailureIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestFailureIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PathSwitchRequestFailureIEValue:", v.id)
	}
}

type S1RemovalFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v S1RemovalFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *S1RemovalFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1RemovalFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalFailureIEs"}}
}
func (S1RemovalFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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
func (v *S1RemovalFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *S1RemovalFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v S1RemovalFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1RemovalFailureIEValue, error) {
	out := S1RemovalFailureIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v S1RemovalFailureIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1RemovalFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1RemovalFailureIEValue:", v.id)
	}
}

type S1RemovalResponseIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEname                *s00.MMEname
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v S1RemovalResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(61):
		return v.rowMMEname != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *S1RemovalResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1RemovalResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalResponseIEs"}}
}
func (S1RemovalResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(61):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
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
func (v *S1RemovalResponseIEValue) AsMMEname() (*s00.MMEname, bool) {
	if v == nil || v.id != s00.ProtocolIEID(61) || v.rowMMEname == nil {
		return nil, false
	}
	return v.rowMMEname, true
}
func (v *S1RemovalResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v S1RemovalResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1RemovalResponseIEValue, error) {
	out := S1RemovalResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(61):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MMEname, error) {
			var v struct{ Value s00.MMEname }
			err := func() error {
				val_value, err := aper.DecodeAlphabetStringAligned(bb, aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = val_value
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
		out.rowMMEname = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v S1RemovalResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1RemovalResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(61):
		if v.rowMMEname == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalResponseIEs.id-MMEname:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MMEname, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MMEname }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeAlphabetStringAligned(bb, string(v.Value), aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMMEname, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1RemovalResponseIEValue:", v.id)
	}
}

type S1SetupFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s14.Cause
	rowTimeToWait             *s00.TimeToWait
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v S1SetupFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(65):
		return v.rowTimeToWait != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *S1SetupFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1SetupFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupFailureIEs"}}
}
func (S1SetupFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(65):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
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
func (v *S1SetupFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *S1SetupFailureIEValue) AsTimeToWait() (*s00.TimeToWait, bool) {
	if v == nil || v.id != s00.ProtocolIEID(65) || v.rowTimeToWait == nil {
		return nil, false
	}
	return v.rowTimeToWait, true
}
func (v *S1SetupFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v S1SetupFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1SetupFailureIEValue, error) {
	out := S1SetupFailureIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(65):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeToWait"})
		value := s00.TimeToWait(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeToWait:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeToWait = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v S1SetupFailureIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1SetupFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(65):
		if v.rowTimeToWait == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupFailureIEs.id-TimeToWait:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeToWait), 6, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1SetupFailureIEValue:", v.id)
	}
}

type UEContextModificationConfirmIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCSGMembershipStatus    *s00.CSGMembershipStatus
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v UEContextModificationConfirmIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *UEContextModificationConfirmIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationConfirmIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs"}}
}
func (UEContextModificationConfirmIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UEContextModificationConfirmIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextModificationConfirmIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextModificationConfirmIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}
func (v *UEContextModificationConfirmIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UEContextModificationConfirmIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationConfirmIEValue, error) {
	out := UEContextModificationConfirmIEValue{id: id}
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
	case s00.ProtocolIEID(146):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
		value := s00.CSGMembershipStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSGMembershipStatus = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextModificationConfirmIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationConfirmIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationConfirmIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationConfirmIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationConfirmIEs.id-CSGMembershipStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSGMembershipStatus), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationConfirmIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationConfirmIEValue:", v.id)
	}
}

type UEContextModificationFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v UEContextModificationFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *UEContextModificationFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs"}}
}
func (UEContextModificationFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UEContextModificationFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextModificationFailureIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextModificationFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *UEContextModificationFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UEContextModificationFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationFailureIEValue, error) {
	out := UEContextModificationFailureIEValue{id: id}
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
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextModificationFailureIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationFailureIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationFailureIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationFailureIEValue:", v.id)
	}
}

type UEContextModificationResponseIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v UEContextModificationResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	}
	return false
}
func (v *UEContextModificationResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationResponseIEs"}}
}
func (UEContextModificationResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UEContextModificationResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextModificationResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextModificationResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UEContextModificationResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationResponseIEValue, error) {
	out := UEContextModificationResponseIEValue{id: id}
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextModificationResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationResponseIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationResponseIEValue:", v.id)
	}
}

type UEContextResumeFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v UEContextResumeFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *UEContextResumeFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextResumeFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs"}}
}
func (UEContextResumeFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UEContextResumeFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextResumeFailureIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextResumeFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *UEContextResumeFailureIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UEContextResumeFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextResumeFailureIEValue, error) {
	out := UEContextResumeFailureIEValue{id: id}
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
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextResumeFailureIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextResumeFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeFailureIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeFailureIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeFailureIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextResumeFailureIEValue:", v.id)
	}
}

type UERadioCapabilityIDMappingResponseIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowUERadioCapabilityID    *s00.UERadioCapabilityID
	rowUERadioCapability      *s00.UERadioCapability
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
}

func (v UERadioCapabilityIDMappingResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}
func (v *UERadioCapabilityIDMappingResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UERadioCapabilityIDMappingResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs"}}
}
func (UERadioCapabilityIDMappingResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
func (v *UERadioCapabilityIDMappingResponseIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}
func (v *UERadioCapabilityIDMappingResponseIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}
func (v *UERadioCapabilityIDMappingResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UERadioCapabilityIDMappingResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UERadioCapabilityIDMappingResponseIEValue, error) {
	out := UERadioCapabilityIDMappingResponseIEValue{id: id}
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
	case s00.ProtocolIEID(74):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapability, error) {
			var v struct{ Value s00.UERadioCapability }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapability(val_value)
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
		out.rowUERadioCapability = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UERadioCapabilityIDMappingResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UERadioCapabilityIDMappingResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-UERadioCapability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapability }{Value: value}
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
		})(*v.rowUERadioCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UERadioCapabilityIDMappingResponseIEValue:", v.id)
	}
}

type MMEConfigurationUpdateFailureIETable struct{}

func MMEConfigurationUpdateFailureIEs() MMEConfigurationUpdateFailureIETable {
	return MMEConfigurationUpdateFailureIETable{}
}
func (MMEConfigurationUpdateFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateFailureIEs"}
		return sealed
	}()
}
func (MMEConfigurationUpdateFailureIETable) Table() s00.MMEConfigurationUpdateFailureIEValueIETable {
	return func() s00.MMEConfigurationUpdateFailureIEValueIETable {
		sealed := s00.MMEConfigurationUpdateFailureIEValueIETable{}
		*s00.BridgeMMEConfigurationUpdateFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEConfigurationUpdateFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateFailureIEs", Row: "id-Cause"}}}
}
func (t MMEConfigurationUpdateFailureIETable) Cause() MMEConfigurationUpdateFailureCauseIEBinding {
	return MMEConfigurationUpdateFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero MMEConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding MMEConfigurationUpdateFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) MMEConfigurationUpdateFailureIEValue {
			return MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *MMEConfigurationUpdateFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (MMEConfigurationUpdateFailureIETable) infoTimeToWait() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(65), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeToWait"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateFailureIEs", Row: "id-TimeToWait"}}}
}
func (t MMEConfigurationUpdateFailureIETable) TimeToWait() MMEConfigurationUpdateFailureTimeToWaitIEBinding {
	return MMEConfigurationUpdateFailureTimeToWaitIEBinding{info: t.infoTimeToWait(), codec: func() s02.TimeToWaitValueCodec {
		sealed := s02.TimeToWaitValueCodec{}
		*s02.BridgeTimeToWaitValueCodecFieldPath(&sealed) = "TimeToWait"
		*s02.BridgeTimeToWaitValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeToWait, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			var zero MMEConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(65), raw)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			value, ok := decoded.AsTimeToWait()
			if !ok {
				var empty s00.TimeToWait
				return empty, fmt.Errorf("binding MMEConfigurationUpdateFailureIEs.id-TimeToWait: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeToWaitValueCodecFieldEncode(&sealed) = func(value s00.TimeToWait, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeToWaitValueCodecFieldCapture(&sealed) = func(v s00.TimeToWait, options aper.DecodeState) (s00.TimeToWait, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APTimeToWait(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeToWaitValueCodecFieldCompare(&sealed) = func(v s00.TimeToWait, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeToWait(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeToWaitValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeToWait"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeToWait) MMEConfigurationUpdateFailureIEValue {
			return MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}
		}, get: func(value *MMEConfigurationUpdateFailureIEValue) (*s00.TimeToWait, bool) {
			return value.AsTimeToWait()
		}}
}
func (MMEConfigurationUpdateFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t MMEConfigurationUpdateFailureIETable) CriticalityDiagnostics() MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding {
	return MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero MMEConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding MMEConfigurationUpdateFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) MMEConfigurationUpdateFailureIEValue {
			return MMEConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *MMEConfigurationUpdateFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t MMEConfigurationUpdateFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEConfigurationUpdateFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(65):
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeToWait requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEConfigurationUpdateFailureIEField{Id: id, Criticality: criticality, Value: MMEConfigurationUpdateFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type PathSwitchRequestFailureIETable struct{}

func PathSwitchRequestFailureIEs() PathSwitchRequestFailureIETable {
	return PathSwitchRequestFailureIETable{}
}
func (PathSwitchRequestFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs"}
		return sealed
	}()
}
func (PathSwitchRequestFailureIETable) Table() s00.PathSwitchRequestFailureIEValueIETable {
	return func() s00.PathSwitchRequestFailureIEValueIETable {
		sealed := s00.PathSwitchRequestFailureIEValueIETable{}
		*s00.BridgePathSwitchRequestFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PathSwitchRequestFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t PathSwitchRequestFailureIETable) MMEUES1APID() PathSwitchRequestFailureMMEUES1APIDIEBinding {
	return PathSwitchRequestFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero PathSwitchRequestFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestFailureIEValue {
			return PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *PathSwitchRequestFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (PathSwitchRequestFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t PathSwitchRequestFailureIETable) ENBUES1APID() PathSwitchRequestFailureENBUES1APIDIEBinding {
	return PathSwitchRequestFailureENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero PathSwitchRequestFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) PathSwitchRequestFailureIEValue {
			return PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *PathSwitchRequestFailureIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (PathSwitchRequestFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs", Row: "id-Cause"}}}
}
func (t PathSwitchRequestFailureIETable) Cause() PathSwitchRequestFailureCauseIEBinding {
	return PathSwitchRequestFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero PathSwitchRequestFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding PathSwitchRequestFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) PathSwitchRequestFailureIEValue {
			return PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *PathSwitchRequestFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (PathSwitchRequestFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t PathSwitchRequestFailureIETable) CriticalityDiagnostics() PathSwitchRequestFailureCriticalityDiagnosticsIEBinding {
	return PathSwitchRequestFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero PathSwitchRequestFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding PathSwitchRequestFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) PathSwitchRequestFailureIEValue {
			return PathSwitchRequestFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *PathSwitchRequestFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t PathSwitchRequestFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PathSwitchRequestFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return PathSwitchRequestFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PathSwitchRequestFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return PathSwitchRequestFailureIEField{Id: id, Criticality: criticality, Value: PathSwitchRequestFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type S1RemovalFailureIETable struct{}

func S1RemovalFailureIEs() S1RemovalFailureIETable { return S1RemovalFailureIETable{} }
func (S1RemovalFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalFailureIEs"}
		return sealed
	}()
}
func (S1RemovalFailureIETable) Table() s00.S1RemovalFailureIEValueIETable {
	return func() s00.S1RemovalFailureIEValueIETable {
		sealed := s00.S1RemovalFailureIEValueIETable{}
		*s00.BridgeS1RemovalFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1RemovalFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalFailureIEs", Row: "id-Cause"}}}
}
func (t S1RemovalFailureIETable) Cause() S1RemovalFailureCauseIEBinding {
	return S1RemovalFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero S1RemovalFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding S1RemovalFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) S1RemovalFailureIEValue {
			return S1RemovalFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *S1RemovalFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (S1RemovalFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t S1RemovalFailureIETable) CriticalityDiagnostics() S1RemovalFailureCriticalityDiagnosticsIEBinding {
	return S1RemovalFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero S1RemovalFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding S1RemovalFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) S1RemovalFailureIEValue {
			return S1RemovalFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *S1RemovalFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t S1RemovalFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1RemovalFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return S1RemovalFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1RemovalFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1RemovalFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1RemovalFailureIEField{Id: id, Criticality: criticality, Value: S1RemovalFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type S1RemovalResponseIETable struct{}

func S1RemovalResponseIEs() S1RemovalResponseIETable { return S1RemovalResponseIETable{} }
func (S1RemovalResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalResponseIEs"}
		return sealed
	}()
}
func (S1RemovalResponseIETable) Table() s00.S1RemovalResponseIEValueIETable {
	return func() s00.S1RemovalResponseIEValueIETable {
		sealed := s00.S1RemovalResponseIEValueIETable{}
		*s00.BridgeS1RemovalResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1RemovalResponseIETable) infoMMEname() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalResponseIEs().ID(), ID: s00.ProtocolIEID(61), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MMEname"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalResponseIEs", Row: "id-MMEname"}}}
}
func (t S1RemovalResponseIETable) MMEname() S1RemovalResponseMMEnameIEBinding {
	return S1RemovalResponseMMEnameIEBinding{info: t.infoMMEname(), codec: func() s01.MMEnameValueCodec {
		sealed := s01.MMEnameValueCodec{}
		*s01.BridgeMMEnameValueCodecFieldPath(&sealed) = "MMEname"
		*s01.BridgeMMEnameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEname, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEname
				return empty, err
			}
			var zero S1RemovalResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(61), raw)
			if err != nil {
				var empty s00.MMEname
				return empty, err
			}
			value, ok := decoded.AsMMEname()
			if !ok {
				var empty s00.MMEname
				return empty, fmt.Errorf("binding S1RemovalResponseIEs.id-MMEname: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEnameValueCodecFieldEncode(&sealed) = func(value s00.MMEname, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalResponseIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEnameValueCodecFieldCapture(&sealed) = func(v s00.MMEname, options aper.DecodeState) (s00.MMEname, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEname(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEnameValueCodecFieldCompare(&sealed) = func(v s00.MMEname, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEname(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEnameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEname"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEname) S1RemovalResponseIEValue {
			return S1RemovalResponseIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}
		}, get: func(value *S1RemovalResponseIEValue) (*s00.MMEname, bool) { return value.AsMMEname() }}
}
func (S1RemovalResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t S1RemovalResponseIETable) CriticalityDiagnostics() S1RemovalResponseCriticalityDiagnosticsIEBinding {
	return S1RemovalResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero S1RemovalResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding S1RemovalResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) S1RemovalResponseIEValue {
			return S1RemovalResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *S1RemovalResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t S1RemovalResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1RemovalResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(61):
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MMEname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return S1RemovalResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1RemovalResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1RemovalResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1RemovalResponseIEField{Id: id, Criticality: criticality, Value: S1RemovalResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type S1SetupFailureIETable struct{}

func S1SetupFailureIEs() S1SetupFailureIETable { return S1SetupFailureIETable{} }
func (S1SetupFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupFailureIEs"}
		return sealed
	}()
}
func (S1SetupFailureIETable) Table() s00.S1SetupFailureIEValueIETable {
	return func() s00.S1SetupFailureIEValueIETable {
		sealed := s00.S1SetupFailureIEValueIETable{}
		*s00.BridgeS1SetupFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1SetupFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupFailureIEs", Row: "id-Cause"}}}
}
func (t S1SetupFailureIETable) Cause() S1SetupFailureCauseIEBinding {
	return S1SetupFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero S1SetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding S1SetupFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) S1SetupFailureIEValue {
			return S1SetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *S1SetupFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (S1SetupFailureIETable) infoTimeToWait() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupFailureIEs().ID(), ID: s00.ProtocolIEID(65), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeToWait"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupFailureIEs", Row: "id-TimeToWait"}}}
}
func (t S1SetupFailureIETable) TimeToWait() S1SetupFailureTimeToWaitIEBinding {
	return S1SetupFailureTimeToWaitIEBinding{info: t.infoTimeToWait(), codec: func() s02.TimeToWaitValueCodec {
		sealed := s02.TimeToWaitValueCodec{}
		*s02.BridgeTimeToWaitValueCodecFieldPath(&sealed) = "TimeToWait"
		*s02.BridgeTimeToWaitValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeToWait, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			var zero S1SetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(65), raw)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			value, ok := decoded.AsTimeToWait()
			if !ok {
				var empty s00.TimeToWait
				return empty, fmt.Errorf("binding S1SetupFailureIEs.id-TimeToWait: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeToWaitValueCodecFieldEncode(&sealed) = func(value s00.TimeToWait, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeToWaitValueCodecFieldCapture(&sealed) = func(v s00.TimeToWait, options aper.DecodeState) (s00.TimeToWait, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APTimeToWait(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeToWaitValueCodecFieldCompare(&sealed) = func(v s00.TimeToWait, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeToWait(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeToWaitValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeToWait"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeToWait) S1SetupFailureIEValue {
			return S1SetupFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}
		}, get: func(value *S1SetupFailureIEValue) (*s00.TimeToWait, bool) { return value.AsTimeToWait() }}
}
func (S1SetupFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t S1SetupFailureIETable) CriticalityDiagnostics() S1SetupFailureCriticalityDiagnosticsIEBinding {
	return S1SetupFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero S1SetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding S1SetupFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) S1SetupFailureIEValue {
			return S1SetupFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *S1SetupFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t S1SetupFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1SetupFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(65):
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeToWait requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return S1SetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1SetupFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1SetupFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1SetupFailureIEField{Id: id, Criticality: criticality, Value: S1SetupFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationConfirmIETable struct{}

func UEContextModificationConfirmIEs() UEContextModificationConfirmIETable {
	return UEContextModificationConfirmIETable{}
}
func (UEContextModificationConfirmIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs"}
		return sealed
	}()
}
func (UEContextModificationConfirmIETable) Table() s00.UEContextModificationConfirmIEValueIETable {
	return func() s00.UEContextModificationConfirmIEValueIETable {
		sealed := s00.UEContextModificationConfirmIEValueIETable{}
		*s00.BridgeUEContextModificationConfirmIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationConfirmIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextModificationConfirmIETable) MMEUES1APID() UEContextModificationConfirmMMEUES1APIDIEBinding {
	return UEContextModificationConfirmMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationConfirmIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationConfirmIEValue {
			return UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationConfirmIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationConfirmIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextModificationConfirmIETable) ENBUES1APID() UEContextModificationConfirmENBUES1APIDIEBinding {
	return UEContextModificationConfirmENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationConfirmIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationConfirmIEValue {
			return UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationConfirmIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationConfirmIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs", Row: "id-CSGMembershipStatus"}}}
}
func (t UEContextModificationConfirmIETable) CSGMembershipStatus() UEContextModificationConfirmCSGMembershipStatusIEBinding {
	return UEContextModificationConfirmCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			var zero UEContextModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding UEContextModificationConfirmIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSGMembershipStatus) UEContextModificationConfirmIEValue {
			return UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *UEContextModificationConfirmIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (UEContextModificationConfirmIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationConfirmIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UEContextModificationConfirmIETable) CriticalityDiagnostics() UEContextModificationConfirmCriticalityDiagnosticsIEBinding {
	return UEContextModificationConfirmCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UEContextModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextModificationConfirmIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UEContextModificationConfirmIEValue {
			return UEContextModificationConfirmIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextModificationConfirmIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UEContextModificationConfirmIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationConfirmIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationConfirmIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationConfirmIEField{Id: id, Criticality: criticality, Value: UEContextModificationConfirmIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationFailureIETable struct{}

func UEContextModificationFailureIEs() UEContextModificationFailureIETable {
	return UEContextModificationFailureIETable{}
}
func (UEContextModificationFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs"}
		return sealed
	}()
}
func (UEContextModificationFailureIETable) Table() s00.UEContextModificationFailureIEValueIETable {
	return func() s00.UEContextModificationFailureIEValueIETable {
		sealed := s00.UEContextModificationFailureIEValueIETable{}
		*s00.BridgeUEContextModificationFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextModificationFailureIETable) MMEUES1APID() UEContextModificationFailureMMEUES1APIDIEBinding {
	return UEContextModificationFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextModificationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationFailureIEValue {
			return UEContextModificationFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationFailureIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextModificationFailureIETable) ENBUES1APID() UEContextModificationFailureENBUES1APIDIEBinding {
	return UEContextModificationFailureENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextModificationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationFailureIEValue {
			return UEContextModificationFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationFailureIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs", Row: "id-Cause"}}}
}
func (t UEContextModificationFailureIETable) Cause() UEContextModificationFailureCauseIEBinding {
	return UEContextModificationFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero UEContextModificationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding UEContextModificationFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) UEContextModificationFailureIEValue {
			return UEContextModificationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextModificationFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (UEContextModificationFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UEContextModificationFailureIETable) CriticalityDiagnostics() UEContextModificationFailureCriticalityDiagnosticsIEBinding {
	return UEContextModificationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UEContextModificationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextModificationFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UEContextModificationFailureIEValue {
			return UEContextModificationFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextModificationFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UEContextModificationFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextModificationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationFailureIEField{Id: id, Criticality: criticality, Value: UEContextModificationFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationResponseIETable struct{}

func UEContextModificationResponseIEs() UEContextModificationResponseIETable {
	return UEContextModificationResponseIETable{}
}
func (UEContextModificationResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationResponseIEs"}
		return sealed
	}()
}
func (UEContextModificationResponseIETable) Table() s00.UEContextModificationResponseIEValueIETable {
	return func() s00.UEContextModificationResponseIEValueIETable {
		sealed := s00.UEContextModificationResponseIEValueIETable{}
		*s00.BridgeUEContextModificationResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextModificationResponseIETable) MMEUES1APID() UEContextModificationResponseMMEUES1APIDIEBinding {
	return UEContextModificationResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextModificationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationResponseIEValue {
			return UEContextModificationResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationResponseIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextModificationResponseIETable) ENBUES1APID() UEContextModificationResponseENBUES1APIDIEBinding {
	return UEContextModificationResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextModificationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationResponseIEValue {
			return UEContextModificationResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationResponseIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UEContextModificationResponseIETable) CriticalityDiagnostics() UEContextModificationResponseCriticalityDiagnosticsIEBinding {
	return UEContextModificationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UEContextModificationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextModificationResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UEContextModificationResponseIEValue {
			return UEContextModificationResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextModificationResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UEContextModificationResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextModificationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationResponseIEField{Id: id, Criticality: criticality, Value: UEContextModificationResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextResumeFailureIETable struct{}

func UEContextResumeFailureIEs() UEContextResumeFailureIETable {
	return UEContextResumeFailureIETable{}
}
func (UEContextResumeFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs"}
		return sealed
	}()
}
func (UEContextResumeFailureIETable) Table() s00.UEContextResumeFailureIEValueIETable {
	return func() s00.UEContextResumeFailureIEValueIETable {
		sealed := s00.UEContextResumeFailureIEValueIETable{}
		*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextResumeFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextResumeFailureIETable) MMEUES1APID() UEContextResumeFailureMMEUES1APIDIEBinding {
	return UEContextResumeFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextResumeFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextResumeFailureIEValue {
			return UEContextResumeFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextResumeFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextResumeFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextResumeFailureIETable) ENBUES1APID() UEContextResumeFailureENBUES1APIDIEBinding {
	return UEContextResumeFailureENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextResumeFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextResumeFailureIEValue {
			return UEContextResumeFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextResumeFailureIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UEContextResumeFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-Cause"}}}
}
func (t UEContextResumeFailureIETable) Cause() UEContextResumeFailureCauseIEBinding {
	return UEContextResumeFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero UEContextResumeFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) UEContextResumeFailureIEValue {
			return UEContextResumeFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextResumeFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (UEContextResumeFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UEContextResumeFailureIETable) CriticalityDiagnostics() UEContextResumeFailureCriticalityDiagnosticsIEBinding {
	return UEContextResumeFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UEContextResumeFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UEContextResumeFailureIEValue {
			return UEContextResumeFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextResumeFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UEContextResumeFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextResumeFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextResumeFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextResumeFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextResumeFailureIEField{Id: id, Criticality: criticality, Value: UEContextResumeFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// TimeToWaitCodec binds the complete APER value type.
func TimeToWaitCodec() s02.TimeToWaitValueCodec {
	return s22.ENBConfigurationUpdateFailureIEs().TimeToWait().Codec()
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldCodec(v *MMEConfigurationUpdateFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldGet(v *MMEConfigurationUpdateFailureCauseIEBinding) *func(*MMEConfigurationUpdateFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldInfo(v *MMEConfigurationUpdateFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldInject(v *MMEConfigurationUpdateFailureCauseIEBinding) *func(s14.Cause) MMEConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldCodec(v *MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldGet(v *MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *func(*MMEConfigurationUpdateFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldInfo(v *MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldInject(v *MMEConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) MMEConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureIEContainerAPERValueFieldContext(v *MMEConfigurationUpdateFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEContainerAPERValueFieldReceived(v *MMEConfigurationUpdateFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEContainerAPERValueFieldReplay(v *MMEConfigurationUpdateFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEContainerAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCapture(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *func(MMEConfigurationUpdateFailureIEContainer, aper.DecodeState) (MMEConfigurationUpdateFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldCompare(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *func(MMEConfigurationUpdateFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldContext(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldDecode(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEContainer, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldEncode(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *func(MMEConfigurationUpdateFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecFieldPath(v *MMEConfigurationUpdateFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureIEContainerValueCodec, a0 MMEConfigurationUpdateFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureIEContainerValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureIEContainerValueCodec, a0 MMEConfigurationUpdateFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureIEFieldAPERValueFieldContext(v *MMEConfigurationUpdateFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEFieldAPERValueFieldReceived(v *MMEConfigurationUpdateFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEFieldAPERValueFieldReplay(v *MMEConfigurationUpdateFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEFieldAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEFieldFieldReceived(v *MMEConfigurationUpdateFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v *MMEConfigurationUpdateFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEFieldFieldStream(v *MMEConfigurationUpdateFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEConfigurationUpdateFailureIEFieldFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(v *MMEConfigurationUpdateFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCapture(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *func(MMEConfigurationUpdateFailureIEField, aper.DecodeState) (MMEConfigurationUpdateFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldCompare(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *func(MMEConfigurationUpdateFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldContext(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldDecode(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEField, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldEncode(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *func(MMEConfigurationUpdateFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecFieldPath(v *MMEConfigurationUpdateFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureIEFieldValueCodec, a0 MMEConfigurationUpdateFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureIEFieldValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureIEFieldValueCodec, a0 MMEConfigurationUpdateFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureIETableMethodInfoCause(v MMEConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeMMEConfigurationUpdateFailureIETableMethodInfoCriticalityDiagnostics(v MMEConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeMMEConfigurationUpdateFailureIETableMethodInfoTimeToWait(v MMEConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoTimeToWait()
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldId(v *MMEConfigurationUpdateFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldIsOpaque(v *MMEConfigurationUpdateFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldOpaque(v *MMEConfigurationUpdateFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldReceived(v *MMEConfigurationUpdateFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldReplay(v *MMEConfigurationUpdateFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldRowCause(v *MMEConfigurationUpdateFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(v *MMEConfigurationUpdateFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldRowTimeToWait(v *MMEConfigurationUpdateFailureIEValue) **s00.TimeToWait {
	return &v.rowTimeToWait
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodCaptureSemantics(v MMEConfigurationUpdateFailureIEValue, a0 aper.SemanticCapture) MMEConfigurationUpdateFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodCompareSemantics(v MMEConfigurationUpdateFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodDecode(v MMEConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEConfigurationUpdateFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodEncode(v MMEConfigurationUpdateFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodEncodeFresh(v MMEConfigurationUpdateFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodMatchesID(v MMEConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodReason(v MMEConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodRule(v MMEConfigurationUpdateFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateFailureTimeToWaitIEBindingFieldCodec(v *MMEConfigurationUpdateFailureTimeToWaitIEBinding) *s02.TimeToWaitValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateFailureTimeToWaitIEBindingFieldGet(v *MMEConfigurationUpdateFailureTimeToWaitIEBinding) *func(*MMEConfigurationUpdateFailureIEValue) (*s00.TimeToWait, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateFailureTimeToWaitIEBindingFieldInfo(v *MMEConfigurationUpdateFailureTimeToWaitIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureTimeToWaitIEBindingFieldInject(v *MMEConfigurationUpdateFailureTimeToWaitIEBinding) *func(s00.TimeToWait) MMEConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureCauseIEBindingFieldCodec(v *PathSwitchRequestFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestFailureCauseIEBindingFieldGet(v *PathSwitchRequestFailureCauseIEBinding) *func(*PathSwitchRequestFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgePathSwitchRequestFailureCauseIEBindingFieldInfo(v *PathSwitchRequestFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureCauseIEBindingFieldInject(v *PathSwitchRequestFailureCauseIEBinding) *func(s14.Cause) PathSwitchRequestFailureIEValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureCriticalityDiagnosticsIEBindingFieldCodec(v *PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestFailureCriticalityDiagnosticsIEBindingFieldGet(v *PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) *func(*PathSwitchRequestFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgePathSwitchRequestFailureCriticalityDiagnosticsIEBindingFieldInfo(v *PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureCriticalityDiagnosticsIEBindingFieldInject(v *PathSwitchRequestFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) PathSwitchRequestFailureIEValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureENBUES1APIDIEBindingFieldCodec(v *PathSwitchRequestFailureENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestFailureENBUES1APIDIEBindingFieldGet(v *PathSwitchRequestFailureENBUES1APIDIEBinding) *func(*PathSwitchRequestFailureIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestFailureENBUES1APIDIEBindingFieldInfo(v *PathSwitchRequestFailureENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureENBUES1APIDIEBindingFieldInject(v *PathSwitchRequestFailureENBUES1APIDIEBinding) *func(s00.ENBUES1APID) PathSwitchRequestFailureIEValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureIEContainerAPERValueFieldContext(v *PathSwitchRequestFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEContainerAPERValueFieldReceived(v *PathSwitchRequestFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEContainerAPERValueFieldReplay(v *PathSwitchRequestFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEContainerAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldCapture(v *PathSwitchRequestFailureIEContainerValueCodec) *func(PathSwitchRequestFailureIEContainer, aper.DecodeState) (PathSwitchRequestFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldCompare(v *PathSwitchRequestFailureIEContainerValueCodec) *func(PathSwitchRequestFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldContext(v *PathSwitchRequestFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldDecode(v *PathSwitchRequestFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEContainer, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldEncode(v *PathSwitchRequestFailureIEContainerValueCodec) *func(PathSwitchRequestFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureIEContainerValueCodecFieldPath(v *PathSwitchRequestFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureIEContainerValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureIEContainerValueCodec, a0 PathSwitchRequestFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureIEContainerValueCodecMethodEncodeChanged(v PathSwitchRequestFailureIEContainerValueCodec, a0 PathSwitchRequestFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestFailureIEFieldAPERValueFieldContext(v *PathSwitchRequestFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEFieldAPERValueFieldReceived(v *PathSwitchRequestFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEFieldAPERValueFieldReplay(v *PathSwitchRequestFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEFieldAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEFieldFieldReceived(v *PathSwitchRequestFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePathSwitchRequestFailureIEFieldFieldReplay(v *PathSwitchRequestFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEFieldFieldStream(v *PathSwitchRequestFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestFailureIEFieldFieldWithoutReplay(v *PathSwitchRequestFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(v *PathSwitchRequestFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestFailureIEFieldMethodUnmarshalAPERFrom(v *PathSwitchRequestFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldCapture(v *PathSwitchRequestFailureIEFieldValueCodec) *func(PathSwitchRequestFailureIEField, aper.DecodeState) (PathSwitchRequestFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldCompare(v *PathSwitchRequestFailureIEFieldValueCodec) *func(PathSwitchRequestFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldContext(v *PathSwitchRequestFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldDecode(v *PathSwitchRequestFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEField, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldEncode(v *PathSwitchRequestFailureIEFieldValueCodec) *func(PathSwitchRequestFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureIEFieldValueCodecFieldPath(v *PathSwitchRequestFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureIEFieldValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureIEFieldValueCodec, a0 PathSwitchRequestFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureIEFieldValueCodecMethodEncodeChanged(v PathSwitchRequestFailureIEFieldValueCodec, a0 PathSwitchRequestFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestFailureIETableMethodInfoCause(v PathSwitchRequestFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgePathSwitchRequestFailureIETableMethodInfoCriticalityDiagnostics(v PathSwitchRequestFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgePathSwitchRequestFailureIETableMethodInfoENBUES1APID(v PathSwitchRequestFailureIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgePathSwitchRequestFailureIETableMethodInfoMMEUES1APID(v PathSwitchRequestFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListAPERValueFieldContext(v *PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListAPERValueFieldReceived(v *PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListAPERValueFieldReplay(v *PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCapture(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldCompare(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldContext(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldDecode(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldEncode(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecFieldPath(v *PathSwitchRequestFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestFailureIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestFailureIEValueFieldId(v *PathSwitchRequestFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePathSwitchRequestFailureIEValueFieldIsOpaque(v *PathSwitchRequestFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgePathSwitchRequestFailureIEValueFieldOpaque(v *PathSwitchRequestFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePathSwitchRequestFailureIEValueFieldReceived(v *PathSwitchRequestFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEValueFieldReplay(v *PathSwitchRequestFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEValueFieldRowCause(v *PathSwitchRequestFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgePathSwitchRequestFailureIEValueFieldRowCriticalityDiagnostics(v *PathSwitchRequestFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgePathSwitchRequestFailureIEValueFieldRowENBUES1APID(v *PathSwitchRequestFailureIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgePathSwitchRequestFailureIEValueFieldRowMMEUES1APID(v *PathSwitchRequestFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgePathSwitchRequestFailureIEValueMethodCaptureSemantics(v PathSwitchRequestFailureIEValue, a0 aper.SemanticCapture) PathSwitchRequestFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgePathSwitchRequestFailureIEValueMethodCompareSemantics(v PathSwitchRequestFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePathSwitchRequestFailureIEValueMethodDecode(v PathSwitchRequestFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PathSwitchRequestFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePathSwitchRequestFailureIEValueMethodEncode(v PathSwitchRequestFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePathSwitchRequestFailureIEValueMethodEncodeFresh(v PathSwitchRequestFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePathSwitchRequestFailureIEValueMethodMatchesID(v PathSwitchRequestFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePathSwitchRequestFailureIEValueMethodReason(v PathSwitchRequestFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePathSwitchRequestFailureIEValueMethodRule(v PathSwitchRequestFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestFailureIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestFailureIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestFailureMMEUES1APIDIEBindingFieldCodec(v *PathSwitchRequestFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestFailureMMEUES1APIDIEBindingFieldGet(v *PathSwitchRequestFailureMMEUES1APIDIEBinding) *func(*PathSwitchRequestFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestFailureMMEUES1APIDIEBindingFieldInfo(v *PathSwitchRequestFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureMMEUES1APIDIEBindingFieldInject(v *PathSwitchRequestFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) PathSwitchRequestFailureIEValue {
	return &v.inject
}
func BridgeS1RemovalFailureCauseIEBindingFieldCodec(v *S1RemovalFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeS1RemovalFailureCauseIEBindingFieldGet(v *S1RemovalFailureCauseIEBinding) *func(*S1RemovalFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeS1RemovalFailureCauseIEBindingFieldInfo(v *S1RemovalFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1RemovalFailureCauseIEBindingFieldInject(v *S1RemovalFailureCauseIEBinding) *func(s14.Cause) S1RemovalFailureIEValue {
	return &v.inject
}
func BridgeS1RemovalFailureCriticalityDiagnosticsIEBindingFieldCodec(v *S1RemovalFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeS1RemovalFailureCriticalityDiagnosticsIEBindingFieldGet(v *S1RemovalFailureCriticalityDiagnosticsIEBinding) *func(*S1RemovalFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeS1RemovalFailureCriticalityDiagnosticsIEBindingFieldInfo(v *S1RemovalFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1RemovalFailureCriticalityDiagnosticsIEBindingFieldInject(v *S1RemovalFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) S1RemovalFailureIEValue {
	return &v.inject
}
func BridgeS1RemovalFailureIEContainerAPERValueFieldContext(v *S1RemovalFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEContainerAPERValueFieldReceived(v *S1RemovalFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEContainerAPERValueFieldReplay(v *S1RemovalFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEContainerAPERValueFieldWithoutReplay(v *S1RemovalFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldCapture(v *S1RemovalFailureIEContainerValueCodec) *func(S1RemovalFailureIEContainer, aper.DecodeState) (S1RemovalFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldCompare(v *S1RemovalFailureIEContainerValueCodec) *func(S1RemovalFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldContext(v *S1RemovalFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldDecode(v *S1RemovalFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1RemovalFailureIEContainer, error) {
	return &v.decode
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldEncode(v *S1RemovalFailureIEContainerValueCodec) *func(S1RemovalFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureIEContainerValueCodecFieldPath(v *S1RemovalFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalFailureIEContainerValueCodecMethodEncodeBudgetValue(v S1RemovalFailureIEContainerValueCodec, a0 S1RemovalFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalFailureIEContainerValueCodecMethodEncodeChanged(v S1RemovalFailureIEContainerValueCodec, a0 S1RemovalFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalFailureIEFieldAPERValueFieldContext(v *S1RemovalFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEFieldAPERValueFieldReceived(v *S1RemovalFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEFieldAPERValueFieldReplay(v *S1RemovalFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEFieldAPERValueFieldWithoutReplay(v *S1RemovalFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEFieldFieldReceived(v *S1RemovalFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1RemovalFailureIEFieldFieldReplay(v *S1RemovalFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEFieldFieldStream(v *S1RemovalFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1RemovalFailureIEFieldFieldWithoutReplay(v *S1RemovalFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEFieldMethodMarshalAPERTo(v *S1RemovalFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1RemovalFailureIEFieldMethodUnmarshalAPERFrom(v *S1RemovalFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldCapture(v *S1RemovalFailureIEFieldValueCodec) *func(S1RemovalFailureIEField, aper.DecodeState) (S1RemovalFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldCompare(v *S1RemovalFailureIEFieldValueCodec) *func(S1RemovalFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldContext(v *S1RemovalFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldDecode(v *S1RemovalFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1RemovalFailureIEField, error) {
	return &v.decode
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldEncode(v *S1RemovalFailureIEFieldValueCodec) *func(S1RemovalFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureIEFieldValueCodecFieldPath(v *S1RemovalFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalFailureIEFieldValueCodecMethodEncodeBudgetValue(v S1RemovalFailureIEFieldValueCodec, a0 S1RemovalFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalFailureIEFieldValueCodecMethodEncodeChanged(v S1RemovalFailureIEFieldValueCodec, a0 S1RemovalFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalFailureIETableMethodInfoCause(v S1RemovalFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeS1RemovalFailureIETableMethodInfoCriticalityDiagnostics(v S1RemovalFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeS1RemovalFailureIEValueERABIEContainerListAPERValueFieldContext(v *S1RemovalFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueERABIEContainerListAPERValueFieldReceived(v *S1RemovalFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEValueERABIEContainerListAPERValueFieldReplay(v *S1RemovalFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldCapture(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *func(S1RemovalFailureIEValueERABIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldCompare(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *func(S1RemovalFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldContext(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldDecode(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldEncode(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *func(S1RemovalFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecFieldPath(v *S1RemovalFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalFailureIEValueERABIEContainerListValueCodec, a0 S1RemovalFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1RemovalFailureIEValueERABIEContainerListValueCodec, a0 S1RemovalFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalFailureIEValueFieldId(v *S1RemovalFailureIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1RemovalFailureIEValueFieldIsOpaque(v *S1RemovalFailureIEValue) *bool       { return &v.isOpaque }
func BridgeS1RemovalFailureIEValueFieldOpaque(v *S1RemovalFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1RemovalFailureIEValueFieldReceived(v *S1RemovalFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEValueFieldReplay(v *S1RemovalFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEValueFieldRowCause(v *S1RemovalFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeS1RemovalFailureIEValueFieldRowCriticalityDiagnostics(v *S1RemovalFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeS1RemovalFailureIEValueMethodCaptureSemantics(v S1RemovalFailureIEValue, a0 aper.SemanticCapture) S1RemovalFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1RemovalFailureIEValueMethodCompareSemantics(v S1RemovalFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1RemovalFailureIEValueMethodDecode(v S1RemovalFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1RemovalFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1RemovalFailureIEValueMethodEncode(v S1RemovalFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1RemovalFailureIEValueMethodEncodeFresh(v S1RemovalFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1RemovalFailureIEValueMethodMatchesID(v S1RemovalFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1RemovalFailureIEValueMethodReason(v S1RemovalFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1RemovalFailureIEValueMethodRule(v S1RemovalFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1RemovalFailureIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *S1RemovalFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1RemovalFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1RemovalFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *func(S1RemovalFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *S1RemovalFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalFailureIEValueProtocolIEContainerListValueCodec, a0 S1RemovalFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1RemovalFailureIEValueProtocolIEContainerListValueCodec, a0 S1RemovalFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseCriticalityDiagnosticsIEBindingFieldCodec(v *S1RemovalResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeS1RemovalResponseCriticalityDiagnosticsIEBindingFieldGet(v *S1RemovalResponseCriticalityDiagnosticsIEBinding) *func(*S1RemovalResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeS1RemovalResponseCriticalityDiagnosticsIEBindingFieldInfo(v *S1RemovalResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1RemovalResponseCriticalityDiagnosticsIEBindingFieldInject(v *S1RemovalResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) S1RemovalResponseIEValue {
	return &v.inject
}
func BridgeS1RemovalResponseIEContainerAPERValueFieldContext(v *S1RemovalResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEContainerAPERValueFieldReceived(v *S1RemovalResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEContainerAPERValueFieldReplay(v *S1RemovalResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEContainerAPERValueFieldWithoutReplay(v *S1RemovalResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldCapture(v *S1RemovalResponseIEContainerValueCodec) *func(S1RemovalResponseIEContainer, aper.DecodeState) (S1RemovalResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldCompare(v *S1RemovalResponseIEContainerValueCodec) *func(S1RemovalResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldContext(v *S1RemovalResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldDecode(v *S1RemovalResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1RemovalResponseIEContainer, error) {
	return &v.decode
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldEncode(v *S1RemovalResponseIEContainerValueCodec) *func(S1RemovalResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseIEContainerValueCodecFieldPath(v *S1RemovalResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalResponseIEContainerValueCodecMethodEncodeBudgetValue(v S1RemovalResponseIEContainerValueCodec, a0 S1RemovalResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalResponseIEContainerValueCodecMethodEncodeChanged(v S1RemovalResponseIEContainerValueCodec, a0 S1RemovalResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseIEFieldAPERValueFieldContext(v *S1RemovalResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEFieldAPERValueFieldReceived(v *S1RemovalResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEFieldAPERValueFieldReplay(v *S1RemovalResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEFieldAPERValueFieldWithoutReplay(v *S1RemovalResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEFieldFieldReceived(v *S1RemovalResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1RemovalResponseIEFieldFieldReplay(v *S1RemovalResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEFieldFieldStream(v *S1RemovalResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1RemovalResponseIEFieldFieldWithoutReplay(v *S1RemovalResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEFieldMethodMarshalAPERTo(v *S1RemovalResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1RemovalResponseIEFieldMethodUnmarshalAPERFrom(v *S1RemovalResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldCapture(v *S1RemovalResponseIEFieldValueCodec) *func(S1RemovalResponseIEField, aper.DecodeState) (S1RemovalResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldCompare(v *S1RemovalResponseIEFieldValueCodec) *func(S1RemovalResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldContext(v *S1RemovalResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldDecode(v *S1RemovalResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1RemovalResponseIEField, error) {
	return &v.decode
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldEncode(v *S1RemovalResponseIEFieldValueCodec) *func(S1RemovalResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseIEFieldValueCodecFieldPath(v *S1RemovalResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalResponseIEFieldValueCodecMethodEncodeBudgetValue(v S1RemovalResponseIEFieldValueCodec, a0 S1RemovalResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalResponseIEFieldValueCodecMethodEncodeChanged(v S1RemovalResponseIEFieldValueCodec, a0 S1RemovalResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseIETableMethodInfoCriticalityDiagnostics(v S1RemovalResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeS1RemovalResponseIETableMethodInfoMMEname(v S1RemovalResponseIETable) s00.FieldInfo {
	return v.infoMMEname()
}
func BridgeS1RemovalResponseIEValueERABIEContainerListAPERValueFieldContext(v *S1RemovalResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueERABIEContainerListAPERValueFieldReceived(v *S1RemovalResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEValueERABIEContainerListAPERValueFieldReplay(v *S1RemovalResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldCapture(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *func(S1RemovalResponseIEValueERABIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldCompare(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *func(S1RemovalResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldContext(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldDecode(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldEncode(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *func(S1RemovalResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecFieldPath(v *S1RemovalResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalResponseIEValueERABIEContainerListValueCodec, a0 S1RemovalResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1RemovalResponseIEValueERABIEContainerListValueCodec, a0 S1RemovalResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseIEValueFieldId(v *S1RemovalResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeS1RemovalResponseIEValueFieldIsOpaque(v *S1RemovalResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeS1RemovalResponseIEValueFieldOpaque(v *S1RemovalResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1RemovalResponseIEValueFieldReceived(v *S1RemovalResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEValueFieldReplay(v *S1RemovalResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEValueFieldRowCriticalityDiagnostics(v *S1RemovalResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeS1RemovalResponseIEValueFieldRowMMEname(v *S1RemovalResponseIEValue) **s00.MMEname {
	return &v.rowMMEname
}
func BridgeS1RemovalResponseIEValueMethodCaptureSemantics(v S1RemovalResponseIEValue, a0 aper.SemanticCapture) S1RemovalResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1RemovalResponseIEValueMethodCompareSemantics(v S1RemovalResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1RemovalResponseIEValueMethodDecode(v S1RemovalResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1RemovalResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1RemovalResponseIEValueMethodEncode(v S1RemovalResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1RemovalResponseIEValueMethodEncodeFresh(v S1RemovalResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1RemovalResponseIEValueMethodMatchesID(v S1RemovalResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1RemovalResponseIEValueMethodReason(v S1RemovalResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1RemovalResponseIEValueMethodRule(v S1RemovalResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1RemovalResponseIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *S1RemovalResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1RemovalResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1RemovalResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *func(S1RemovalResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *S1RemovalResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalResponseIEValueProtocolIEContainerListValueCodec, a0 S1RemovalResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1RemovalResponseIEValueProtocolIEContainerListValueCodec, a0 S1RemovalResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalResponseMMEnameIEBindingFieldCodec(v *S1RemovalResponseMMEnameIEBinding) *s01.MMEnameValueCodec {
	return &v.codec
}
func BridgeS1RemovalResponseMMEnameIEBindingFieldGet(v *S1RemovalResponseMMEnameIEBinding) *func(*S1RemovalResponseIEValue) (*s00.MMEname, bool) {
	return &v.get
}
func BridgeS1RemovalResponseMMEnameIEBindingFieldInfo(v *S1RemovalResponseMMEnameIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1RemovalResponseMMEnameIEBindingFieldInject(v *S1RemovalResponseMMEnameIEBinding) *func(s00.MMEname) S1RemovalResponseIEValue {
	return &v.inject
}
func BridgeS1SetupFailureCauseIEBindingFieldCodec(v *S1SetupFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeS1SetupFailureCauseIEBindingFieldGet(v *S1SetupFailureCauseIEBinding) *func(*S1SetupFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeS1SetupFailureCauseIEBindingFieldInfo(v *S1SetupFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupFailureCauseIEBindingFieldInject(v *S1SetupFailureCauseIEBinding) *func(s14.Cause) S1SetupFailureIEValue {
	return &v.inject
}
func BridgeS1SetupFailureCriticalityDiagnosticsIEBindingFieldCodec(v *S1SetupFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeS1SetupFailureCriticalityDiagnosticsIEBindingFieldGet(v *S1SetupFailureCriticalityDiagnosticsIEBinding) *func(*S1SetupFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeS1SetupFailureCriticalityDiagnosticsIEBindingFieldInfo(v *S1SetupFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupFailureCriticalityDiagnosticsIEBindingFieldInject(v *S1SetupFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) S1SetupFailureIEValue {
	return &v.inject
}
func BridgeS1SetupFailureIEContainerAPERValueFieldContext(v *S1SetupFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEContainerAPERValueFieldReceived(v *S1SetupFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEContainerAPERValueFieldReplay(v *S1SetupFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEContainerAPERValueFieldWithoutReplay(v *S1SetupFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEContainerValueCodecFieldCapture(v *S1SetupFailureIEContainerValueCodec) *func(S1SetupFailureIEContainer, aper.DecodeState) (S1SetupFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureIEContainerValueCodecFieldCompare(v *S1SetupFailureIEContainerValueCodec) *func(S1SetupFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureIEContainerValueCodecFieldContext(v *S1SetupFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEContainerValueCodecFieldDecode(v *S1SetupFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1SetupFailureIEContainer, error) {
	return &v.decode
}
func BridgeS1SetupFailureIEContainerValueCodecFieldEncode(v *S1SetupFailureIEContainerValueCodec) *func(S1SetupFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureIEContainerValueCodecFieldPath(v *S1SetupFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupFailureIEContainerValueCodecMethodEncodeBudgetValue(v S1SetupFailureIEContainerValueCodec, a0 S1SetupFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupFailureIEContainerValueCodecMethodEncodeChanged(v S1SetupFailureIEContainerValueCodec, a0 S1SetupFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupFailureIEFieldAPERValueFieldContext(v *S1SetupFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEFieldAPERValueFieldReceived(v *S1SetupFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEFieldAPERValueFieldReplay(v *S1SetupFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEFieldAPERValueFieldWithoutReplay(v *S1SetupFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEFieldFieldReceived(v *S1SetupFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1SetupFailureIEFieldFieldReplay(v *S1SetupFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEFieldFieldStream(v *S1SetupFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1SetupFailureIEFieldFieldWithoutReplay(v *S1SetupFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEFieldMethodMarshalAPERTo(v *S1SetupFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1SetupFailureIEFieldMethodUnmarshalAPERFrom(v *S1SetupFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupFailureIEFieldValueCodecFieldCapture(v *S1SetupFailureIEFieldValueCodec) *func(S1SetupFailureIEField, aper.DecodeState) (S1SetupFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureIEFieldValueCodecFieldCompare(v *S1SetupFailureIEFieldValueCodec) *func(S1SetupFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureIEFieldValueCodecFieldContext(v *S1SetupFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEFieldValueCodecFieldDecode(v *S1SetupFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1SetupFailureIEField, error) {
	return &v.decode
}
func BridgeS1SetupFailureIEFieldValueCodecFieldEncode(v *S1SetupFailureIEFieldValueCodec) *func(S1SetupFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureIEFieldValueCodecFieldPath(v *S1SetupFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupFailureIEFieldValueCodecMethodEncodeBudgetValue(v S1SetupFailureIEFieldValueCodec, a0 S1SetupFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupFailureIEFieldValueCodecMethodEncodeChanged(v S1SetupFailureIEFieldValueCodec, a0 S1SetupFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupFailureIETableMethodInfoCause(v S1SetupFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeS1SetupFailureIETableMethodInfoCriticalityDiagnostics(v S1SetupFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeS1SetupFailureIETableMethodInfoTimeToWait(v S1SetupFailureIETable) s00.FieldInfo {
	return v.infoTimeToWait()
}
func BridgeS1SetupFailureIEValueERABIEContainerListAPERValueFieldContext(v *S1SetupFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueERABIEContainerListAPERValueFieldReceived(v *S1SetupFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEValueERABIEContainerListAPERValueFieldReplay(v *S1SetupFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1SetupFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldCapture(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *func(S1SetupFailureIEValueERABIEContainerList, aper.DecodeState) (S1SetupFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldCompare(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *func(S1SetupFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldContext(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldDecode(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldEncode(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *func(S1SetupFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecFieldPath(v *S1SetupFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupFailureIEValueERABIEContainerListValueCodec, a0 S1SetupFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1SetupFailureIEValueERABIEContainerListValueCodec, a0 S1SetupFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupFailureIEValueFieldId(v *S1SetupFailureIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1SetupFailureIEValueFieldIsOpaque(v *S1SetupFailureIEValue) *bool       { return &v.isOpaque }
func BridgeS1SetupFailureIEValueFieldOpaque(v *S1SetupFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1SetupFailureIEValueFieldReceived(v *S1SetupFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEValueFieldReplay(v *S1SetupFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEValueFieldRowCause(v *S1SetupFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeS1SetupFailureIEValueFieldRowCriticalityDiagnostics(v *S1SetupFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeS1SetupFailureIEValueFieldRowTimeToWait(v *S1SetupFailureIEValue) **s00.TimeToWait {
	return &v.rowTimeToWait
}
func BridgeS1SetupFailureIEValueMethodCaptureSemantics(v S1SetupFailureIEValue, a0 aper.SemanticCapture) S1SetupFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1SetupFailureIEValueMethodCompareSemantics(v S1SetupFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1SetupFailureIEValueMethodDecode(v S1SetupFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1SetupFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1SetupFailureIEValueMethodEncode(v S1SetupFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1SetupFailureIEValueMethodEncodeFresh(v S1SetupFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1SetupFailureIEValueMethodMatchesID(v S1SetupFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1SetupFailureIEValueMethodReason(v S1SetupFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1SetupFailureIEValueMethodRule(v S1SetupFailureIEValue) aper.SourceRule { return v.rule() }
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1SetupFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1SetupFailureIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *S1SetupFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1SetupFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1SetupFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1SetupFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *func(S1SetupFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *S1SetupFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupFailureIEValueProtocolIEContainerListValueCodec, a0 S1SetupFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1SetupFailureIEValueProtocolIEContainerListValueCodec, a0 S1SetupFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupFailureTimeToWaitIEBindingFieldCodec(v *S1SetupFailureTimeToWaitIEBinding) *s02.TimeToWaitValueCodec {
	return &v.codec
}
func BridgeS1SetupFailureTimeToWaitIEBindingFieldGet(v *S1SetupFailureTimeToWaitIEBinding) *func(*S1SetupFailureIEValue) (*s00.TimeToWait, bool) {
	return &v.get
}
func BridgeS1SetupFailureTimeToWaitIEBindingFieldInfo(v *S1SetupFailureTimeToWaitIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupFailureTimeToWaitIEBindingFieldInject(v *S1SetupFailureTimeToWaitIEBinding) *func(s00.TimeToWait) S1SetupFailureIEValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmCSGMembershipStatusIEBindingFieldCodec(v *UEContextModificationConfirmCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgeUEContextModificationConfirmCSGMembershipStatusIEBindingFieldGet(v *UEContextModificationConfirmCSGMembershipStatusIEBinding) *func(*UEContextModificationConfirmIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgeUEContextModificationConfirmCSGMembershipStatusIEBindingFieldInfo(v *UEContextModificationConfirmCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmCSGMembershipStatusIEBindingFieldInject(v *UEContextModificationConfirmCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) UEContextModificationConfirmIEValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextModificationConfirmCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextModificationConfirmCriticalityDiagnosticsIEBindingFieldGet(v *UEContextModificationConfirmCriticalityDiagnosticsIEBinding) *func(*UEContextModificationConfirmIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextModificationConfirmCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextModificationConfirmCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmCriticalityDiagnosticsIEBindingFieldInject(v *UEContextModificationConfirmCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextModificationConfirmIEValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmENBUES1APIDIEBindingFieldCodec(v *UEContextModificationConfirmENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationConfirmENBUES1APIDIEBindingFieldGet(v *UEContextModificationConfirmENBUES1APIDIEBinding) *func(*UEContextModificationConfirmIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationConfirmENBUES1APIDIEBindingFieldInfo(v *UEContextModificationConfirmENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmENBUES1APIDIEBindingFieldInject(v *UEContextModificationConfirmENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextModificationConfirmIEValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmIEContainerAPERValueFieldContext(v *UEContextModificationConfirmIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEContainerAPERValueFieldReceived(v *UEContextModificationConfirmIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEContainerAPERValueFieldReplay(v *UEContextModificationConfirmIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEContainerAPERValueFieldWithoutReplay(v *UEContextModificationConfirmIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldCapture(v *UEContextModificationConfirmIEContainerValueCodec) *func(UEContextModificationConfirmIEContainer, aper.DecodeState) (UEContextModificationConfirmIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldCompare(v *UEContextModificationConfirmIEContainerValueCodec) *func(UEContextModificationConfirmIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldContext(v *UEContextModificationConfirmIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(v *UEContextModificationConfirmIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirmIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(v *UEContextModificationConfirmIEContainerValueCodec) *func(UEContextModificationConfirmIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmIEContainerValueCodecFieldPath(v *UEContextModificationConfirmIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmIEContainerValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmIEContainerValueCodec, a0 UEContextModificationConfirmIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmIEContainerValueCodecMethodEncodeChanged(v UEContextModificationConfirmIEContainerValueCodec, a0 UEContextModificationConfirmIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmIEFieldAPERValueFieldContext(v *UEContextModificationConfirmIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEFieldAPERValueFieldReceived(v *UEContextModificationConfirmIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEFieldAPERValueFieldReplay(v *UEContextModificationConfirmIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEFieldAPERValueFieldWithoutReplay(v *UEContextModificationConfirmIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEFieldFieldReceived(v *UEContextModificationConfirmIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextModificationConfirmIEFieldFieldReplay(v *UEContextModificationConfirmIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEFieldFieldStream(v *UEContextModificationConfirmIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationConfirmIEFieldFieldWithoutReplay(v *UEContextModificationConfirmIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(v *UEContextModificationConfirmIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationConfirmIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldCapture(v *UEContextModificationConfirmIEFieldValueCodec) *func(UEContextModificationConfirmIEField, aper.DecodeState) (UEContextModificationConfirmIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldCompare(v *UEContextModificationConfirmIEFieldValueCodec) *func(UEContextModificationConfirmIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldContext(v *UEContextModificationConfirmIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldDecode(v *UEContextModificationConfirmIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirmIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldEncode(v *UEContextModificationConfirmIEFieldValueCodec) *func(UEContextModificationConfirmIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmIEFieldValueCodecFieldPath(v *UEContextModificationConfirmIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmIEFieldValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmIEFieldValueCodec, a0 UEContextModificationConfirmIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmIEFieldValueCodecMethodEncodeChanged(v UEContextModificationConfirmIEFieldValueCodec, a0 UEContextModificationConfirmIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmIETableMethodInfoCSGMembershipStatus(v UEContextModificationConfirmIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeUEContextModificationConfirmIETableMethodInfoCriticalityDiagnostics(v UEContextModificationConfirmIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextModificationConfirmIETableMethodInfoENBUES1APID(v UEContextModificationConfirmIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationConfirmIETableMethodInfoMMEUES1APID(v UEContextModificationConfirmIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListAPERValueFieldContext(v *UEContextModificationConfirmIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextModificationConfirmIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextModificationConfirmIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationConfirmIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationConfirmIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmIEValueERABIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationConfirmIEValueERABIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmIEValueFieldId(v *UEContextModificationConfirmIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationConfirmIEValueFieldIsOpaque(v *UEContextModificationConfirmIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationConfirmIEValueFieldOpaque(v *UEContextModificationConfirmIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationConfirmIEValueFieldReceived(v *UEContextModificationConfirmIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEValueFieldReplay(v *UEContextModificationConfirmIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEValueFieldRowCSGMembershipStatus(v *UEContextModificationConfirmIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeUEContextModificationConfirmIEValueFieldRowCriticalityDiagnostics(v *UEContextModificationConfirmIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextModificationConfirmIEValueFieldRowENBUES1APID(v *UEContextModificationConfirmIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationConfirmIEValueFieldRowMMEUES1APID(v *UEContextModificationConfirmIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationConfirmIEValueMethodCaptureSemantics(v UEContextModificationConfirmIEValue, a0 aper.SemanticCapture) UEContextModificationConfirmIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationConfirmIEValueMethodCompareSemantics(v UEContextModificationConfirmIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationConfirmIEValueMethodDecode(v UEContextModificationConfirmIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextModificationConfirmIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextModificationConfirmIEValueMethodEncode(v UEContextModificationConfirmIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextModificationConfirmIEValueMethodEncodeFresh(v UEContextModificationConfirmIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationConfirmIEValueMethodMatchesID(v UEContextModificationConfirmIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationConfirmIEValueMethodReason(v UEContextModificationConfirmIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextModificationConfirmIEValueMethodRule(v UEContextModificationConfirmIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationConfirmIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirmIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationConfirmIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationConfirmIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmMMEUES1APIDIEBindingFieldCodec(v *UEContextModificationConfirmMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationConfirmMMEUES1APIDIEBindingFieldGet(v *UEContextModificationConfirmMMEUES1APIDIEBinding) *func(*UEContextModificationConfirmIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationConfirmMMEUES1APIDIEBindingFieldInfo(v *UEContextModificationConfirmMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmMMEUES1APIDIEBindingFieldInject(v *UEContextModificationConfirmMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextModificationConfirmIEValue {
	return &v.inject
}
func BridgeUEContextModificationFailureCauseIEBindingFieldCodec(v *UEContextModificationFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeUEContextModificationFailureCauseIEBindingFieldGet(v *UEContextModificationFailureCauseIEBinding) *func(*UEContextModificationFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeUEContextModificationFailureCauseIEBindingFieldInfo(v *UEContextModificationFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationFailureCauseIEBindingFieldInject(v *UEContextModificationFailureCauseIEBinding) *func(s14.Cause) UEContextModificationFailureIEValue {
	return &v.inject
}
func BridgeUEContextModificationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextModificationFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextModificationFailureCriticalityDiagnosticsIEBindingFieldGet(v *UEContextModificationFailureCriticalityDiagnosticsIEBinding) *func(*UEContextModificationFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextModificationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextModificationFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationFailureCriticalityDiagnosticsIEBindingFieldInject(v *UEContextModificationFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextModificationFailureIEValue {
	return &v.inject
}
func BridgeUEContextModificationFailureENBUES1APIDIEBindingFieldCodec(v *UEContextModificationFailureENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationFailureENBUES1APIDIEBindingFieldGet(v *UEContextModificationFailureENBUES1APIDIEBinding) *func(*UEContextModificationFailureIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationFailureENBUES1APIDIEBindingFieldInfo(v *UEContextModificationFailureENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationFailureENBUES1APIDIEBindingFieldInject(v *UEContextModificationFailureENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextModificationFailureIEValue {
	return &v.inject
}
func BridgeUEContextModificationFailureIEContainerAPERValueFieldContext(v *UEContextModificationFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEContainerAPERValueFieldReceived(v *UEContextModificationFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEContainerAPERValueFieldReplay(v *UEContextModificationFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEContainerAPERValueFieldWithoutReplay(v *UEContextModificationFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldCapture(v *UEContextModificationFailureIEContainerValueCodec) *func(UEContextModificationFailureIEContainer, aper.DecodeState) (UEContextModificationFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldCompare(v *UEContextModificationFailureIEContainerValueCodec) *func(UEContextModificationFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldContext(v *UEContextModificationFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(v *UEContextModificationFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailureIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(v *UEContextModificationFailureIEContainerValueCodec) *func(UEContextModificationFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureIEContainerValueCodecFieldPath(v *UEContextModificationFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureIEContainerValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureIEContainerValueCodec, a0 UEContextModificationFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureIEContainerValueCodecMethodEncodeChanged(v UEContextModificationFailureIEContainerValueCodec, a0 UEContextModificationFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureIEFieldAPERValueFieldContext(v *UEContextModificationFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEFieldAPERValueFieldReceived(v *UEContextModificationFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEFieldAPERValueFieldReplay(v *UEContextModificationFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEFieldAPERValueFieldWithoutReplay(v *UEContextModificationFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEFieldFieldReceived(v *UEContextModificationFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextModificationFailureIEFieldFieldReplay(v *UEContextModificationFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEFieldFieldStream(v *UEContextModificationFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationFailureIEFieldFieldWithoutReplay(v *UEContextModificationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(v *UEContextModificationFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldCapture(v *UEContextModificationFailureIEFieldValueCodec) *func(UEContextModificationFailureIEField, aper.DecodeState) (UEContextModificationFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldCompare(v *UEContextModificationFailureIEFieldValueCodec) *func(UEContextModificationFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldContext(v *UEContextModificationFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldDecode(v *UEContextModificationFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailureIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldEncode(v *UEContextModificationFailureIEFieldValueCodec) *func(UEContextModificationFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureIEFieldValueCodecFieldPath(v *UEContextModificationFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureIEFieldValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureIEFieldValueCodec, a0 UEContextModificationFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureIEFieldValueCodecMethodEncodeChanged(v UEContextModificationFailureIEFieldValueCodec, a0 UEContextModificationFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureIETableMethodInfoCause(v UEContextModificationFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUEContextModificationFailureIETableMethodInfoCriticalityDiagnostics(v UEContextModificationFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextModificationFailureIETableMethodInfoENBUES1APID(v UEContextModificationFailureIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationFailureIETableMethodInfoMMEUES1APID(v UEContextModificationFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListAPERValueFieldContext(v *UEContextModificationFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextModificationFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextModificationFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *func(UEContextModificationFailureIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *func(UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *func(UEContextModificationFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureIEValueERABIEContainerListValueCodec, a0 UEContextModificationFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationFailureIEValueERABIEContainerListValueCodec, a0 UEContextModificationFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureIEValueFieldId(v *UEContextModificationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationFailureIEValueFieldIsOpaque(v *UEContextModificationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationFailureIEValueFieldOpaque(v *UEContextModificationFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationFailureIEValueFieldReceived(v *UEContextModificationFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEValueFieldReplay(v *UEContextModificationFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEValueFieldRowCause(v *UEContextModificationFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeUEContextModificationFailureIEValueFieldRowCriticalityDiagnostics(v *UEContextModificationFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextModificationFailureIEValueFieldRowENBUES1APID(v *UEContextModificationFailureIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationFailureIEValueFieldRowMMEUES1APID(v *UEContextModificationFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationFailureIEValueMethodCaptureSemantics(v UEContextModificationFailureIEValue, a0 aper.SemanticCapture) UEContextModificationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationFailureIEValueMethodCompareSemantics(v UEContextModificationFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationFailureIEValueMethodDecode(v UEContextModificationFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextModificationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextModificationFailureIEValueMethodEncode(v UEContextModificationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextModificationFailureIEValueMethodEncodeFresh(v UEContextModificationFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationFailureIEValueMethodMatchesID(v UEContextModificationFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationFailureIEValueMethodReason(v UEContextModificationFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextModificationFailureIEValueMethodRule(v UEContextModificationFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationFailureIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureMMEUES1APIDIEBindingFieldCodec(v *UEContextModificationFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationFailureMMEUES1APIDIEBindingFieldGet(v *UEContextModificationFailureMMEUES1APIDIEBinding) *func(*UEContextModificationFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationFailureMMEUES1APIDIEBindingFieldInfo(v *UEContextModificationFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationFailureMMEUES1APIDIEBindingFieldInject(v *UEContextModificationFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextModificationFailureIEValue {
	return &v.inject
}
func BridgeUEContextModificationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextModificationResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextModificationResponseCriticalityDiagnosticsIEBindingFieldGet(v *UEContextModificationResponseCriticalityDiagnosticsIEBinding) *func(*UEContextModificationResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextModificationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextModificationResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationResponseCriticalityDiagnosticsIEBindingFieldInject(v *UEContextModificationResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextModificationResponseIEValue {
	return &v.inject
}
func BridgeUEContextModificationResponseENBUES1APIDIEBindingFieldCodec(v *UEContextModificationResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationResponseENBUES1APIDIEBindingFieldGet(v *UEContextModificationResponseENBUES1APIDIEBinding) *func(*UEContextModificationResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationResponseENBUES1APIDIEBindingFieldInfo(v *UEContextModificationResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationResponseENBUES1APIDIEBindingFieldInject(v *UEContextModificationResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextModificationResponseIEValue {
	return &v.inject
}
func BridgeUEContextModificationResponseIEContainerAPERValueFieldContext(v *UEContextModificationResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEContainerAPERValueFieldReceived(v *UEContextModificationResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEContainerAPERValueFieldReplay(v *UEContextModificationResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEContainerAPERValueFieldWithoutReplay(v *UEContextModificationResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldCapture(v *UEContextModificationResponseIEContainerValueCodec) *func(UEContextModificationResponseIEContainer, aper.DecodeState) (UEContextModificationResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldCompare(v *UEContextModificationResponseIEContainerValueCodec) *func(UEContextModificationResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldContext(v *UEContextModificationResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(v *UEContextModificationResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponseIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(v *UEContextModificationResponseIEContainerValueCodec) *func(UEContextModificationResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseIEContainerValueCodecFieldPath(v *UEContextModificationResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseIEContainerValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseIEContainerValueCodec, a0 UEContextModificationResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseIEContainerValueCodecMethodEncodeChanged(v UEContextModificationResponseIEContainerValueCodec, a0 UEContextModificationResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseIEFieldAPERValueFieldContext(v *UEContextModificationResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEFieldAPERValueFieldReceived(v *UEContextModificationResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEFieldAPERValueFieldReplay(v *UEContextModificationResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEFieldAPERValueFieldWithoutReplay(v *UEContextModificationResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEFieldFieldReceived(v *UEContextModificationResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextModificationResponseIEFieldFieldReplay(v *UEContextModificationResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEFieldFieldStream(v *UEContextModificationResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationResponseIEFieldFieldWithoutReplay(v *UEContextModificationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(v *UEContextModificationResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldCapture(v *UEContextModificationResponseIEFieldValueCodec) *func(UEContextModificationResponseIEField, aper.DecodeState) (UEContextModificationResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldCompare(v *UEContextModificationResponseIEFieldValueCodec) *func(UEContextModificationResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldContext(v *UEContextModificationResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldDecode(v *UEContextModificationResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponseIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldEncode(v *UEContextModificationResponseIEFieldValueCodec) *func(UEContextModificationResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseIEFieldValueCodecFieldPath(v *UEContextModificationResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseIEFieldValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseIEFieldValueCodec, a0 UEContextModificationResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseIEFieldValueCodecMethodEncodeChanged(v UEContextModificationResponseIEFieldValueCodec, a0 UEContextModificationResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseIETableMethodInfoCriticalityDiagnostics(v UEContextModificationResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextModificationResponseIETableMethodInfoENBUES1APID(v UEContextModificationResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationResponseIETableMethodInfoMMEUES1APID(v UEContextModificationResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListAPERValueFieldContext(v *UEContextModificationResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextModificationResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextModificationResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *func(UEContextModificationResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *func(UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *func(UEContextModificationResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseIEValueERABIEContainerListValueCodec, a0 UEContextModificationResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationResponseIEValueERABIEContainerListValueCodec, a0 UEContextModificationResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseIEValueFieldId(v *UEContextModificationResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationResponseIEValueFieldIsOpaque(v *UEContextModificationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationResponseIEValueFieldOpaque(v *UEContextModificationResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationResponseIEValueFieldReceived(v *UEContextModificationResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEValueFieldReplay(v *UEContextModificationResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEValueFieldRowCriticalityDiagnostics(v *UEContextModificationResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextModificationResponseIEValueFieldRowENBUES1APID(v *UEContextModificationResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationResponseIEValueFieldRowMMEUES1APID(v *UEContextModificationResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationResponseIEValueMethodCaptureSemantics(v UEContextModificationResponseIEValue, a0 aper.SemanticCapture) UEContextModificationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationResponseIEValueMethodCompareSemantics(v UEContextModificationResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationResponseIEValueMethodDecode(v UEContextModificationResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextModificationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextModificationResponseIEValueMethodEncode(v UEContextModificationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextModificationResponseIEValueMethodEncodeFresh(v UEContextModificationResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationResponseIEValueMethodMatchesID(v UEContextModificationResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationResponseIEValueMethodReason(v UEContextModificationResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextModificationResponseIEValueMethodRule(v UEContextModificationResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationResponseIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseMMEUES1APIDIEBindingFieldCodec(v *UEContextModificationResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationResponseMMEUES1APIDIEBindingFieldGet(v *UEContextModificationResponseMMEUES1APIDIEBinding) *func(*UEContextModificationResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationResponseMMEUES1APIDIEBindingFieldInfo(v *UEContextModificationResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationResponseMMEUES1APIDIEBindingFieldInject(v *UEContextModificationResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextModificationResponseIEValue {
	return &v.inject
}
func BridgeUEContextResumeFailureCauseIEBindingFieldCodec(v *UEContextResumeFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeUEContextResumeFailureCauseIEBindingFieldGet(v *UEContextResumeFailureCauseIEBinding) *func(*UEContextResumeFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeUEContextResumeFailureCauseIEBindingFieldInfo(v *UEContextResumeFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeFailureCauseIEBindingFieldInject(v *UEContextResumeFailureCauseIEBinding) *func(s14.Cause) UEContextResumeFailureIEValue {
	return &v.inject
}
func BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextResumeFailureCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldGet(v *UEContextResumeFailureCriticalityDiagnosticsIEBinding) *func(*UEContextResumeFailureIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextResumeFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldInject(v *UEContextResumeFailureCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextResumeFailureIEValue {
	return &v.inject
}
func BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldCodec(v *UEContextResumeFailureENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldGet(v *UEContextResumeFailureENBUES1APIDIEBinding) *func(*UEContextResumeFailureIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldInfo(v *UEContextResumeFailureENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldInject(v *UEContextResumeFailureENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextResumeFailureIEValue {
	return &v.inject
}
func BridgeUEContextResumeFailureIEContainerAPERValueFieldContext(v *UEContextResumeFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEContainerAPERValueFieldReceived(v *UEContextResumeFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEContainerAPERValueFieldReplay(v *UEContextResumeFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEContainerAPERValueFieldWithoutReplay(v *UEContextResumeFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldCapture(v *UEContextResumeFailureIEContainerValueCodec) *func(UEContextResumeFailureIEContainer, aper.DecodeState) (UEContextResumeFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldCompare(v *UEContextResumeFailureIEContainerValueCodec) *func(UEContextResumeFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldContext(v *UEContextResumeFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(v *UEContextResumeFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailureIEContainer, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(v *UEContextResumeFailureIEContainerValueCodec) *func(UEContextResumeFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEContainerValueCodecFieldPath(v *UEContextResumeFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureIEContainerValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureIEContainerValueCodec, a0 UEContextResumeFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureIEContainerValueCodecMethodEncodeChanged(v UEContextResumeFailureIEContainerValueCodec, a0 UEContextResumeFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureIEFieldAPERValueFieldContext(v *UEContextResumeFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEFieldAPERValueFieldReceived(v *UEContextResumeFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEFieldAPERValueFieldReplay(v *UEContextResumeFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEFieldAPERValueFieldWithoutReplay(v *UEContextResumeFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEFieldFieldReceived(v *UEContextResumeFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextResumeFailureIEFieldFieldReplay(v *UEContextResumeFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEFieldFieldStream(v *UEContextResumeFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v *UEContextResumeFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(v *UEContextResumeFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(v *UEContextResumeFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldCapture(v *UEContextResumeFailureIEFieldValueCodec) *func(UEContextResumeFailureIEField, aper.DecodeState) (UEContextResumeFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldCompare(v *UEContextResumeFailureIEFieldValueCodec) *func(UEContextResumeFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldContext(v *UEContextResumeFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldDecode(v *UEContextResumeFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailureIEField, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldEncode(v *UEContextResumeFailureIEFieldValueCodec) *func(UEContextResumeFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEFieldValueCodecFieldPath(v *UEContextResumeFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureIEFieldValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureIEFieldValueCodec, a0 UEContextResumeFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureIEFieldValueCodecMethodEncodeChanged(v UEContextResumeFailureIEFieldValueCodec, a0 UEContextResumeFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureIETableMethodInfoCause(v UEContextResumeFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUEContextResumeFailureIETableMethodInfoCriticalityDiagnostics(v UEContextResumeFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextResumeFailureIETableMethodInfoENBUES1APID(v UEContextResumeFailureIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextResumeFailureIETableMethodInfoMMEUES1APID(v UEContextResumeFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListAPERValueFieldContext(v *UEContextResumeFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextResumeFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextResumeFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextResumeFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *func(UEContextResumeFailureIEValueERABIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *func(UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldContext(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *func(UEContextResumeFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldPath(v *UEContextResumeFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureIEValueERABIEContainerListValueCodec, a0 UEContextResumeFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextResumeFailureIEValueERABIEContainerListValueCodec, a0 UEContextResumeFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureIEValueFieldId(v *UEContextResumeFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextResumeFailureIEValueFieldIsOpaque(v *UEContextResumeFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextResumeFailureIEValueFieldOpaque(v *UEContextResumeFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextResumeFailureIEValueFieldReceived(v *UEContextResumeFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEValueFieldReplay(v *UEContextResumeFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEValueFieldRowCause(v *UEContextResumeFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeUEContextResumeFailureIEValueFieldRowCriticalityDiagnostics(v *UEContextResumeFailureIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextResumeFailureIEValueFieldRowENBUES1APID(v *UEContextResumeFailureIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextResumeFailureIEValueFieldRowMMEUES1APID(v *UEContextResumeFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextResumeFailureIEValueMethodCaptureSemantics(v UEContextResumeFailureIEValue, a0 aper.SemanticCapture) UEContextResumeFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextResumeFailureIEValueMethodCompareSemantics(v UEContextResumeFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextResumeFailureIEValueMethodDecode(v UEContextResumeFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextResumeFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextResumeFailureIEValueMethodEncode(v UEContextResumeFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextResumeFailureIEValueMethodEncodeFresh(v UEContextResumeFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextResumeFailureIEValueMethodMatchesID(v UEContextResumeFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextResumeFailureIEValueMethodReason(v UEContextResumeFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextResumeFailureIEValueMethodRule(v UEContextResumeFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextResumeFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextResumeFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextResumeFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolIEContainerList, aper.DecodeState) (UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureIEValueProtocolIEContainerListValueCodec, a0 UEContextResumeFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextResumeFailureIEValueProtocolIEContainerListValueCodec, a0 UEContextResumeFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureMMEUES1APIDIEBindingFieldCodec(v *UEContextResumeFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextResumeFailureMMEUES1APIDIEBindingFieldGet(v *UEContextResumeFailureMMEUES1APIDIEBinding) *func(*UEContextResumeFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextResumeFailureMMEUES1APIDIEBindingFieldInfo(v *UEContextResumeFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeFailureMMEUES1APIDIEBindingFieldInject(v *UEContextResumeFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextResumeFailureIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldGet(v *UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) *func(*UERadioCapabilityIDMappingResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBindingFieldInject(v *UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UERadioCapabilityIDMappingResponseIEValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseIEContainerValueCodec, a0 UERadioCapabilityIDMappingResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseIEContainerValueCodec, a0 UERadioCapabilityIDMappingResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReceived(v *UERadioCapabilityIDMappingResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v *UERadioCapabilityIDMappingResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldStream(v *UERadioCapabilityIDMappingResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(v *UERadioCapabilityIDMappingResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseIEFieldValueCodec, a0 UERadioCapabilityIDMappingResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseIEFieldValueCodec, a0 UERadioCapabilityIDMappingResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec, a0 UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec, a0 UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(v *UERadioCapabilityIDMappingResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldIsOpaque(v *UERadioCapabilityIDMappingResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldOpaque(v *UERadioCapabilityIDMappingResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(v *UERadioCapabilityIDMappingResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(v *UERadioCapabilityIDMappingResponseIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(v *UERadioCapabilityIDMappingResponseIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodCaptureSemantics(v UERadioCapabilityIDMappingResponseIEValue, a0 aper.SemanticCapture) UERadioCapabilityIDMappingResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodCompareSemantics(v UERadioCapabilityIDMappingResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodDecode(v UERadioCapabilityIDMappingResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UERadioCapabilityIDMappingResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodEncode(v UERadioCapabilityIDMappingResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodEncodeFresh(v UERadioCapabilityIDMappingResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodMatchesID(v UERadioCapabilityIDMappingResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodReason(v UERadioCapabilityIDMappingResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(v UERadioCapabilityIDMappingResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
