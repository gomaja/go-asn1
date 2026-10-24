// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s40 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s40

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverCommandIEContainer is the concrete ProtocolIEContainer[HandoverCommandIEValue].
type HandoverCommandIEContainer []HandoverCommandIEField

// HandoverCommandIEField is the concrete ProtocolIEField[HandoverCommandIEValue].
type HandoverCommandIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverCommandIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEField) WithoutReplay() HandoverCommandIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverCommandIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverCommandIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverCommandIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCommandIEField{}
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
	var zero HandoverCommandIEValue

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

// PathSwitchRequestIEContainer is the concrete ProtocolIEContainer[PathSwitchRequestIEValue].
type PathSwitchRequestIEContainer []PathSwitchRequestIEField

// PathSwitchRequestIEField is the concrete ProtocolIEField[PathSwitchRequestIEValue].
type PathSwitchRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PathSwitchRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEField) WithoutReplay() PathSwitchRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PathSwitchRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PathSwitchRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *PathSwitchRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestIEField{}
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
	var zero PathSwitchRequestIEValue

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

// ERABSetupRequestIEContainer is the concrete ProtocolIEContainer[ERABSetupRequestIEValue].
type ERABSetupRequestIEContainer []ERABSetupRequestIEField

// ERABSetupRequestIEField is the concrete ProtocolIEField[ERABSetupRequestIEValue].
type ERABSetupRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABSetupRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEField) WithoutReplay() ERABSetupRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABSetupRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupRequestIEField{}
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
	var zero ERABSetupRequestIEValue

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

// ERABModifyRequestIEContainer is the concrete ProtocolIEContainer[ERABModifyRequestIEValue].
type ERABModifyRequestIEContainer []ERABModifyRequestIEField

// ERABModifyRequestIEField is the concrete ProtocolIEField[ERABModifyRequestIEValue].
type ERABModifyRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModifyRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEField) WithoutReplay() ERABModifyRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABModifyRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyRequestIEField{}
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
	var zero ERABModifyRequestIEValue

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

// DownlinkS1cdma2000tunnellingIEContainer is the concrete ProtocolIEContainer[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEContainer []DownlinkS1cdma2000tunnellingIEField

// DownlinkS1cdma2000tunnellingIEField is the concrete ProtocolIEField[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DownlinkS1cdma2000tunnellingIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEField) WithoutReplay() DownlinkS1cdma2000tunnellingIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DownlinkS1cdma2000tunnellingIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DownlinkS1cdma2000tunnellingIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *DownlinkS1cdma2000tunnellingIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkS1cdma2000tunnellingIEField{}
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
	var zero DownlinkS1cdma2000tunnellingIEValue

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
func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(v *DownlinkS1cdma2000tunnellingIEContainer, s *aper.SemanticCapture) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(v *DownlinkS1cdma2000tunnellingIEContainer, s *aper.SemanticComparison) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyRequestIEValueCaptureS1APProtocolIEContainer(v *ERABModifyRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeERABModifyRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyRequestIEValueCompareS1APProtocolIEContainer(v *ERABModifyRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeERABModifyRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupRequestIEValueCaptureS1APProtocolIEContainer(v *ERABSetupRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeERABSetupRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupRequestIEValueCompareS1APProtocolIEContainer(v *ERABSetupRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeERABSetupRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverCommandIEValueCaptureS1APProtocolIEContainer(v *HandoverCommandIEContainer, s *aper.SemanticCapture) {
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
			BridgeHandoverCommandIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCommandIEValueCompareS1APProtocolIEContainer(v *HandoverCommandIEContainer, s *aper.SemanticComparison) {
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
			BridgeHandoverCommandIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding is the concrete IEBinding[ERABSubjecttoDataForwardingList, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABSubjecttoDataForwardingListValueCodec
	inject func(s16.ERABSubjecttoDataForwardingList,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s16.ERABSubjecttoDataForwardingList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) Codec() s16.ERABSubjecttoDataForwardingListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) New(value s16.ERABSubjecttoDataForwardingList,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s16.ERABSubjecttoDataForwardingList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding is the concrete IEBinding[Cdma2000HOStatus, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000HOStatusValueCodec
	inject func(s00.Cdma2000HOStatus,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000HOStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) Codec() s00.Cdma2000HOStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) New(value s00.Cdma2000HOStatus,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000HOStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s00.Cdma2000HOStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding is the concrete IEBinding[Cdma2000RATType, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000RATTypeValueCodec
	inject func(s00.Cdma2000RATType,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000RATType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Codec() s00.Cdma2000RATTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) New(value s00.Cdma2000RATType,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s00.Cdma2000RATType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding is the concrete IEBinding[Cdma2000PDU, DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000PDUValueCodec
	inject func(s00.Cdma2000PDU,

	) DownlinkS1cdma2000tunnellingIEValue

	get func(*DownlinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000PDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) Codec() s00.Cdma2000PDUValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) New(value s00.Cdma2000PDU,

) (DownlinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000PDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) Get(field *DownlinkS1cdma2000tunnellingIEField) (*s00.Cdma2000PDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, ERABModifyRequestIEValue].
type ERABModifyRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABModifyRequestIEValue

	get func(*ERABModifyRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModifyRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABModifyRequestIEField, error) {
	if b.inject == nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyRequestMMEUES1APIDIEBinding) Get(field *ERABModifyRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyRequestENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, ERABModifyRequestIEValue].
type ERABModifyRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABModifyRequestIEValue

	get func(*ERABModifyRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModifyRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABModifyRequestIEField, error) {
	if b.inject == nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyRequestENBUES1APIDIEBinding) Get(field *ERABModifyRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyRequestUEAggregateMaximumBitrateIEBinding is the concrete IEBinding[UEAggregateMaximumBitrate, ERABModifyRequestIEValue].
type ERABModifyRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) ERABModifyRequestIEValue

	get func(*ERABModifyRequestIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyRequestUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (ERABModifyRequestIEField, error) {
	if b.inject == nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyRequestUEAggregateMaximumBitrateIEBinding) Get(field *ERABModifyRequestIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding is the concrete IEBinding[ERABToBeModifiedListBearerModReq, ERABModifyRequestIEValue].
type ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding struct {
	info   s00.FieldInfo
	codec  s25.ERABToBeModifiedListBearerModReqValueCodec
	inject func(s25.ERABToBeModifiedListBearerModReq,

	) ERABModifyRequestIEValue

	get func(*ERABModifyRequestIEValue,

	) (*s25.ERABToBeModifiedListBearerModReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) Codec() s25.ERABToBeModifiedListBearerModReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) New(value s25.ERABToBeModifiedListBearerModReq,

) (ERABModifyRequestIEField, error) {
	if b.inject == nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) Get(field *ERABModifyRequestIEField) (*s25.ERABToBeModifiedListBearerModReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyRequestSecondaryRATDataUsageRequestIEBinding is the concrete IEBinding[SecondaryRATDataUsageRequest, ERABModifyRequestIEValue].
type ERABModifyRequestSecondaryRATDataUsageRequestIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SecondaryRATDataUsageRequestValueCodec
	inject func(s00.SecondaryRATDataUsageRequest,

	) ERABModifyRequestIEValue

	get func(*ERABModifyRequestIEValue,

	) (*s00.SecondaryRATDataUsageRequest,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) Codec() s01.SecondaryRATDataUsageRequestValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) New(value s00.SecondaryRATDataUsageRequest,

) (ERABModifyRequestIEField, error) {
	if b.inject == nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) Get(field *ERABModifyRequestIEField) (*s00.SecondaryRATDataUsageRequest,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, ERABSetupRequestIEValue].
type ERABSetupRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABSetupRequestIEValue

	get func(*ERABSetupRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABSetupRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABSetupRequestIEField, error) {
	if b.inject == nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupRequestMMEUES1APIDIEBinding) Get(field *ERABSetupRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupRequestENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, ERABSetupRequestIEValue].
type ERABSetupRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABSetupRequestIEValue

	get func(*ERABSetupRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABSetupRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABSetupRequestIEField, error) {
	if b.inject == nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupRequestENBUES1APIDIEBinding) Get(field *ERABSetupRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupRequestUEAggregateMaximumBitrateIEBinding is the concrete IEBinding[UEAggregateMaximumBitrate, ERABSetupRequestIEValue].
type ERABSetupRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) ERABSetupRequestIEValue

	get func(*ERABSetupRequestIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupRequestUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupRequestUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (ERABSetupRequestIEField, error) {
	if b.inject == nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupRequestUEAggregateMaximumBitrateIEBinding) Get(field *ERABSetupRequestIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding is the concrete IEBinding[ERABToBeSetupListBearerSUReq, ERABSetupRequestIEValue].
type ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding struct {
	info   s00.FieldInfo
	codec  s29.ERABToBeSetupListBearerSUReqValueCodec
	inject func(s29.ERABToBeSetupListBearerSUReq,

	) ERABSetupRequestIEValue

	get func(*ERABSetupRequestIEValue,

	) (*s29.ERABToBeSetupListBearerSUReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) Codec() s29.ERABToBeSetupListBearerSUReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) New(value s29.ERABToBeSetupListBearerSUReq,

) (ERABSetupRequestIEField, error) {
	if b.inject == nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) Get(field *ERABSetupRequestIEField) (*s29.ERABToBeSetupListBearerSUReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverCommandIEValue].
type HandoverCommandMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCommandMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandMMEUES1APIDIEBinding) Get(field *HandoverCommandIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverCommandIEValue].
type HandoverCommandENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCommandENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandENBUES1APIDIEBinding) Get(field *HandoverCommandIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandHandoverTypeIEBinding is the concrete IEBinding[HandoverType, HandoverCommandIEValue].
type HandoverCommandHandoverTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.HandoverTypeValueCodec
	inject func(s00.HandoverType,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s00.HandoverType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandHandoverTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandHandoverTypeIEBinding) Codec() s00.HandoverTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCommandHandoverTypeIEBinding) New(value s00.HandoverType,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeHandoverTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandHandoverTypeIEBinding) Get(field *HandoverCommandIEField) (*s00.HandoverType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandNASSecurityParametersfromEUTRANIEBinding is the concrete IEBinding[NASSecurityParametersfromEUTRAN, HandoverCommandIEValue].
type HandoverCommandNASSecurityParametersfromEUTRANIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASSecurityParametersfromEUTRANValueCodec
	inject func(s00.NASSecurityParametersfromEUTRAN,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s00.NASSecurityParametersfromEUTRAN,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandNASSecurityParametersfromEUTRANIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandNASSecurityParametersfromEUTRANIEBinding) Codec() s01.NASSecurityParametersfromEUTRANValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCommandNASSecurityParametersfromEUTRANIEBinding) New(value s00.NASSecurityParametersfromEUTRAN,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandNASSecurityParametersfromEUTRANIEBinding) Get(field *HandoverCommandIEField) (*s00.NASSecurityParametersfromEUTRAN,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandERABSubjecttoDataForwardingListIEBinding is the concrete IEBinding[ERABSubjecttoDataForwardingList, HandoverCommandIEValue].
type HandoverCommandERABSubjecttoDataForwardingListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABSubjecttoDataForwardingListValueCodec
	inject func(s16.ERABSubjecttoDataForwardingList,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s16.ERABSubjecttoDataForwardingList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandERABSubjecttoDataForwardingListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandERABSubjecttoDataForwardingListIEBinding) Codec() s16.ERABSubjecttoDataForwardingListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCommandERABSubjecttoDataForwardingListIEBinding) New(value s16.ERABSubjecttoDataForwardingList,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandERABSubjecttoDataForwardingListIEBinding) Get(field *HandoverCommandIEField) (*s16.ERABSubjecttoDataForwardingList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandERABListIEBinding is the concrete IEBinding[ERABList, HandoverCommandIEValue].
type HandoverCommandERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCommandERABListIEBinding) New(value s16.ERABList,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandERABListIEBinding) Get(field *HandoverCommandIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandTargetToSourceTransparentContainerIEBinding is the concrete IEBinding[TargetToSourceTransparentContainer, HandoverCommandIEValue].
type HandoverCommandTargetToSourceTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  s01.TargetToSourceTransparentContainerValueCodec
	inject func(s00.TargetToSourceTransparentContainer,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s00.TargetToSourceTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandTargetToSourceTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverCommandTargetToSourceTransparentContainerIEBinding) Codec() s01.TargetToSourceTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCommandTargetToSourceTransparentContainerIEBinding) New(value s00.TargetToSourceTransparentContainer,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandTargetToSourceTransparentContainerIEBinding) Get(field *HandoverCommandIEField) (*s00.TargetToSourceTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCommandCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, HandoverCommandIEValue].
type HandoverCommandCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) HandoverCommandIEValue

	get func(*HandoverCommandIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCommandCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (HandoverCommandIEField, error) {
	if b.inject == nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCommandCriticalityDiagnosticsIEBinding) Get(field *HandoverCommandIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, PathSwitchRequestIEValue].
type PathSwitchRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestERABToBeSwitchedDLListIEBinding is the concrete IEBinding[ERABToBeSwitchedDLList, PathSwitchRequestIEValue].
type PathSwitchRequestERABToBeSwitchedDLListIEBinding struct {
	info   s00.FieldInfo
	codec  s30.ERABToBeSwitchedDLListValueCodec
	inject func(s30.ERABToBeSwitchedDLList,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s30.ERABToBeSwitchedDLList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Codec() s30.ERABToBeSwitchedDLListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) New(value s30.ERABToBeSwitchedDLList,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeERABToBeSwitchedDLListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Get(field *PathSwitchRequestIEField) (*s30.ERABToBeSwitchedDLList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, PathSwitchRequestIEValue].
type PathSwitchRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestEUTRANCGIIEBinding is the concrete IEBinding[EUTRANCGI, PathSwitchRequestIEValue].
type PathSwitchRequestEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Get(field *PathSwitchRequestIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestTAIIEBinding is the concrete IEBinding[TAI, PathSwitchRequestIEValue].
type PathSwitchRequestTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s31.TAI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s31.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestTAIIEBinding) New(value s31.TAI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestTAIIEBinding) Get(field *PathSwitchRequestIEField) (*s31.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestUESecurityCapabilitiesIEBinding is the concrete IEBinding[UESecurityCapabilities, PathSwitchRequestIEValue].
type PathSwitchRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCSGIdIEBinding is the concrete IEBinding[CSGId, PathSwitchRequestIEValue].
type PathSwitchRequestCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCSGIdIEBinding) New(value s00.CSGId,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCSGIdIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCellAccessModeIEBinding is the concrete IEBinding[CellAccessMode, PathSwitchRequestIEValue].
type PathSwitchRequestCellAccessModeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellAccessModeValueCodec
	inject func(s00.CellAccessMode,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CellAccessMode,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Codec() s00.CellAccessModeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCellAccessModeIEBinding) New(value s00.CellAccessMode,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellAccessModeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CellAccessMode,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestGUMMEIIEBinding is the concrete IEBinding[GUMMEI, PathSwitchRequestIEValue].
type PathSwitchRequestGUMMEIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIValueCodec
	inject func(s18.GUMMEI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s18.GUMMEI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Codec() s18.GUMMEIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestGUMMEIIEBinding) New(value s18.GUMMEI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Get(field *PathSwitchRequestIEField) (*s18.GUMMEI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCSGMembershipStatusIEBinding is the concrete IEBinding[CSGMembershipStatus, PathSwitchRequestIEValue].
type PathSwitchRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestTunnelInformationIEBinding is the concrete IEBinding[TunnelInformation, PathSwitchRequestIEValue].
type PathSwitchRequestTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s35.TunnelInformationValueCodec
	inject func(s34.TunnelInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s34.TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Codec() s35.TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestTunnelInformationIEBinding) New(value s34.TunnelInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeTunnelInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s34.TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestLHNIDIEBinding is the concrete IEBinding[LHNID, PathSwitchRequestIEValue].
type PathSwitchRequestLHNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LHNIDValueCodec
	inject func(s00.LHNID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.LHNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestLHNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestLHNIDIEBinding) Codec() s01.LHNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestLHNIDIEBinding) New(value s00.LHNID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLHNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestLHNIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.LHNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestRRCEstablishmentCauseIEBinding is the concrete IEBinding[RRCEstablishmentCause, PathSwitchRequestIEValue].
type PathSwitchRequestRRCEstablishmentCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RRCEstablishmentCauseValueCodec
	inject func(s00.RRCEstablishmentCause,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.RRCEstablishmentCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Codec() s01.RRCEstablishmentCauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) New(value s00.RRCEstablishmentCause,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Get(field *PathSwitchRequestIEField) (*s00.RRCEstablishmentCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestNRUESecurityCapabilitiesIEBinding is the concrete IEBinding[NRUESecurityCapabilities, PathSwitchRequestIEValue].
type PathSwitchRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestPSCellInformationIEBinding is the concrete IEBinding[PSCellInformation, PathSwitchRequestIEValue].
type PathSwitchRequestPSCellInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PSCellInformationValueCodec
	inject func(s20.PSCellInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s20.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Codec() s20.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestPSCellInformationIEBinding) New(value s20.PSCellInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s20.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestLTENTNTAIInformationIEBinding is the concrete IEBinding[LTENTNTAIInformation, PathSwitchRequestIEValue].
type PathSwitchRequestLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkS1cdma2000tunnellingValueCodec is the concrete ValueCodec[DownlinkS1cdma2000tunnelling].
type DownlinkS1cdma2000tunnellingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnelling,

		error)
	encode func(DownlinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnelling, aper.DecodeState,

	) (DownlinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(DownlinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingValueCodec) New(value DownlinkS1cdma2000tunnelling,

) (DownlinkS1cdma2000tunnellingAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingValueCodec) encodeChanged(value DownlinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestValueCodec is the concrete ValueCodec[ERABModifyRequest].
type ERABModifyRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequest,

		error)
	encode func(ERABModifyRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequest, aper.DecodeState,

	) (ERABModifyRequest, aper.Snapshot,

	)
	compare func(ERABModifyRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestValueCodec) New(value ERABModifyRequest,

) (ERABModifyRequestAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestValueCodec) EncodeAPER(value ERABModifyRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestValueCodec) encodeBudgetValue(value ERABModifyRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestValueCodec) encodeChanged(value ERABModifyRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestValueCodec is the concrete ValueCodec[ERABSetupRequest].
type ERABSetupRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequest,

		error)
	encode func(ERABSetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequest, aper.DecodeState,

	) (ERABSetupRequest, aper.Snapshot,

	)
	compare func(ERABSetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestValueCodec) New(value ERABSetupRequest,

) (ERABSetupRequestAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestValueCodec) EncodeAPER(value ERABSetupRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestValueCodec) encodeBudgetValue(value ERABSetupRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestValueCodec) encodeChanged(value ERABSetupRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandValueCodec is the concrete ValueCodec[HandoverCommand].
type HandoverCommandValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommand,

		error)
	encode func(HandoverCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommand, aper.DecodeState,

	) (HandoverCommand, aper.Snapshot,

	)
	compare func(HandoverCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandValueCodec) New(value HandoverCommand,

) (HandoverCommandAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandValueCodec) EncodeAPER(value HandoverCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandValueCodec) encodeBudgetValue(value HandoverCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandValueCodec) encodeChanged(value HandoverCommand,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeHandoverCommandIEValueValidateS1APIEContainer(fields HandoverCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABSetupRequestIEValueValidateS1APIEContainer(fields ERABSetupRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABModifyRequestIEValueValidateS1APIEContainer(fields ERABModifyRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields DownlinkS1cdma2000tunnellingIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func DownlinkS1cdma2000tunnellingIEValueERABIEContainerListCodec(table s00.DownlinkS1cdma2000tunnellingIEValueIETable) DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec {
	codec := DownlinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{}
	}
	return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerList(value), err
	}, encode: func(value DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABModifyRequestIEValueERABIEContainerListCodec(table s00.ERABModifyRequestIEValueIETable) ERABModifyRequestIEValueERABIEContainerListValueCodec {
	codec := ERABModifyRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABModifyRequestIEValueERABIEContainerListValueCodec{}
	}
	return ERABModifyRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModifyRequestIEValueERABIEContainerList(value), err
	}, encode: func(value ERABModifyRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModifyRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABModifyRequestIEValueERABIEContainerList, options aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABModifyRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABSetupRequestIEValueERABIEContainerListCodec(table s00.ERABSetupRequestIEValueIETable) ERABSetupRequestIEValueERABIEContainerListValueCodec {
	codec := ERABSetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABSetupRequestIEValueERABIEContainerListValueCodec{}
	}
	return ERABSetupRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSetupRequestIEValueERABIEContainerList(value), err
	}, encode: func(value ERABSetupRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABSetupRequestIEValueERABIEContainerList, options aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABSetupRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func HandoverCommandIEValueERABIEContainerListCodec(table s00.HandoverCommandIEValueIETable) HandoverCommandIEValueERABIEContainerListValueCodec {
	codec := HandoverCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverCommandIEValueERABIEContainerListValueCodec{}
	}
	return HandoverCommandIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverCommandIEValueERABIEContainerList(value), err
	}, encode: func(value HandoverCommandIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverCommandIEContainer(value), fresh, budget)
	}, capture: func(v HandoverCommandIEValueERABIEContainerList, options aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverCommandIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverCommandIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverCommandIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func DownlinkS1cdma2000tunnellingIEValueIEFieldTableCodec(table s00.DownlinkS1cdma2000tunnellingIEValueIETable) DownlinkS1cdma2000tunnellingIEFieldValueCodec {
	if !*s00.BridgeDownlinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return DownlinkS1cdma2000tunnellingIEFieldValueCodec{}
	}
	return DownlinkS1cdma2000tunnellingIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, error) {
		var field DownlinkS1cdma2000tunnellingIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field DownlinkS1cdma2000tunnellingIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v DownlinkS1cdma2000tunnellingIEField, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v DownlinkS1cdma2000tunnellingIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABModifyRequestIEValueIEFieldTableCodec(table s00.ERABModifyRequestIEValueIETable) ERABModifyRequestIEFieldValueCodec {
	if !*s00.BridgeERABModifyRequestIEValueIETableFieldBound(&table) {
		return ERABModifyRequestIEFieldValueCodec{}
	}
	return ERABModifyRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModifyRequestIEField, error) {
		var field ERABModifyRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field ERABModifyRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABModifyRequestIEField, options aper.DecodeState) (ERABModifyRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABModifyRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABSetupRequestIEValueIEFieldTableCodec(table s00.ERABSetupRequestIEValueIETable) ERABSetupRequestIEFieldValueCodec {
	if !*s00.BridgeERABSetupRequestIEValueIETableFieldBound(&table) {
		return ERABSetupRequestIEFieldValueCodec{}
	}
	return ERABSetupRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSetupRequestIEField, error) {
		var field ERABSetupRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field ERABSetupRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABSetupRequestIEField, options aper.DecodeState) (ERABSetupRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABSetupRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func HandoverCommandIEValueIEFieldTableCodec(table s00.HandoverCommandIEValueIETable) HandoverCommandIEFieldValueCodec {
	if !*s00.BridgeHandoverCommandIEValueIETableFieldBound(&table) {
		return HandoverCommandIEFieldValueCodec{}
	}
	return HandoverCommandIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverCommandIEField, error) {
		var field HandoverCommandIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field HandoverCommandIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v HandoverCommandIEField, options aper.DecodeState) (HandoverCommandIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverCommandIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v HandoverCommandIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverCommandIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func DownlinkS1cdma2000tunnellingIEValueIETableCodec(table s00.DownlinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) DownlinkS1cdma2000tunnellingIEContainerValueCodec {
	if !*s00.BridgeDownlinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return DownlinkS1cdma2000tunnellingIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return DownlinkS1cdma2000tunnellingIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields DownlinkS1cdma2000tunnellingIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field DownlinkS1cdma2000tunnellingIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields DownlinkS1cdma2000tunnellingIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v DownlinkS1cdma2000tunnellingIEContainer, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v DownlinkS1cdma2000tunnellingIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func ERABModifyRequestIEValueIETableCodec(table s00.ERABModifyRequestIEValueIETable, bounds aper.ListBounds) ERABModifyRequestIEContainerValueCodec {
	if !*s00.BridgeERABModifyRequestIEValueIETableFieldBound(&table) {
		return ERABModifyRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABModifyRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModifyRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABModifyRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABModifyRequestIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields ERABModifyRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v ERABModifyRequestIEContainer, options aper.DecodeState) (ERABModifyRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABModifyRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func ERABSetupRequestIEValueIETableCodec(table s00.ERABSetupRequestIEValueIETable, bounds aper.ListBounds) ERABSetupRequestIEContainerValueCodec {
	if !*s00.BridgeERABSetupRequestIEValueIETableFieldBound(&table) {
		return ERABSetupRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABSetupRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSetupRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABSetupRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABSetupRequestIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields ERABSetupRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v ERABSetupRequestIEContainer, options aper.DecodeState) (ERABSetupRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABSetupRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func HandoverCommandIEValueIETableCodec(table s00.HandoverCommandIEValueIETable, bounds aper.ListBounds) HandoverCommandIEContainerValueCodec {
	if !*s00.BridgeHandoverCommandIEValueIETableFieldBound(&table) {
		return HandoverCommandIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverCommandIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverCommandIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverCommandIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverCommandIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields HandoverCommandIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v HandoverCommandIEContainer, options aper.DecodeState) (HandoverCommandIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverCommandIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v HandoverCommandIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverCommandIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkS1cdma2000tunnellingIEValueIETable) DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABModifyRequestIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyRequestIEValueIETable) ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModifyRequestIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABModifyRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModifyRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABModifyRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABModifyRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABModifyRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func ERABSetupRequestIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupRequestIEValueIETable) ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSetupRequestIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABSetupRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABSetupRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABSetupRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func HandoverCommandIEValueProtocolErrorIEContainerListCodec(table s00.HandoverCommandIEValueIETable) HandoverCommandIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverCommandIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return HandoverCommandIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverCommandIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value HandoverCommandIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverCommandIEContainer(value), fresh, budget)
	}, capture: func(v HandoverCommandIEValueProtocolErrorIEContainerList, options aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverCommandIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverCommandIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeHandoverCommandIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec(table s00.DownlinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkS1cdma2000tunnellingIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{}
	}
	return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList(value), err
	}, encode: func(value DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, options aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func ERABModifyRequestIEValueProtocolIEContainerListCodec(table s00.ERABModifyRequestIEValueIETable, bounds aper.ListBounds) ERABModifyRequestIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABModifyRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABModifyRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModifyRequestIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABModifyRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModifyRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABModifyRequestIEValueProtocolIEContainerList, options aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABModifyRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModifyRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func ERABSetupRequestIEValueProtocolIEContainerListCodec(table s00.ERABSetupRequestIEValueIETable, bounds aper.ListBounds) ERABSetupRequestIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABSetupRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABSetupRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABSetupRequestIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABSetupRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v ERABSetupRequestIEValueProtocolIEContainerList, options aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABSetupRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABSetupRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func HandoverCommandIEValueProtocolIEContainerListCodec(table s00.HandoverCommandIEValueIETable, bounds aper.ListBounds) HandoverCommandIEValueProtocolIEContainerListValueCodec {
	codec := HandoverCommandIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return HandoverCommandIEValueProtocolIEContainerListValueCodec{}
	}
	return HandoverCommandIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverCommandIEValueProtocolIEContainerList(value), err
	}, encode: func(value HandoverCommandIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverCommandIEContainer(value), fresh, budget)
	}, capture: func(v HandoverCommandIEValueProtocolIEContainerList, options aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverCommandIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v HandoverCommandIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverCommandIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// downlinkS1cdma2000tunnellingIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) DownlinkS1cdma2000tunnellingIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (DownlinkS1cdma2000tunnellingIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v *DownlinkS1cdma2000tunnellingIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v *DownlinkS1cdma2000tunnellingIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABModifyRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyRequestIEValue].
type ERABModifyRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABModifyRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABModifyRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyRequestIEValueCaptureS1APProtocolIEField(v *ERABModifyRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABModifyRequestIEValueCompareS1APProtocolIEField(v *ERABModifyRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABSetupRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupRequestIEValue].
type ERABSetupRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABSetupRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABSetupRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupRequestIEValueCaptureS1APProtocolIEField(v *ERABSetupRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABSetupRequestIEValueCompareS1APProtocolIEField(v *ERABSetupRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// handoverCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverCommandIEValue].
type HandoverCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) HandoverCommandIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (HandoverCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverCommandIEValueCaptureS1APProtocolIEField(v *HandoverCommandIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeHandoverCommandIEValueCompareS1APProtocolIEField(v *HandoverCommandIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// DownlinkS1cdma2000tunnellingAPERValue is the concrete APERValue[DownlinkS1cdma2000tunnelling].
type DownlinkS1cdma2000tunnellingAPERValue struct {
	context s00.BridgeCodecContext
	Value   DownlinkS1cdma2000tunnelling

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestAPERValue is the concrete APERValue[ERABModifyRequest].
type ERABModifyRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestAPERValue) WithoutReplay() ERABModifyRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestAPERValue is the concrete APERValue[ERABSetupRequest].
type ERABSetupRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestAPERValue) WithoutReplay() ERABSetupRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandAPERValue is the concrete APERValue[HandoverCommand].
type HandoverCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandAPERValue) WithoutReplay() HandoverCommandAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, error)
	encode  func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot)
	compare func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) New(value DownlinkS1cdma2000tunnellingIEValueERABIEContainerList) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeChanged(value DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkS1cdma2000tunnellingIEValueERABIEContainerList is the concrete ERABIEContainerList[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEValueERABIEContainerList []DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModifyRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, error)
	encode  func(ERABModifyRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequestIEValueERABIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModifyRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestIEValueERABIEContainerListValueCodec) New(value ERABModifyRequestIEValueERABIEContainerList) (ERABModifyRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModifyRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModifyRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModifyRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABModifyRequestIEValue].
type ERABModifyRequestIEValueERABIEContainerList []ERABModifyRequestIEValueProtocolIESingleContainer

func BridgeERABModifyRequestIEValueCaptureS1APERABIEContainerList(v *ERABModifyRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABModifyRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyRequestIEValueCompareS1APERABIEContainerList(v *ERABModifyRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABModifyRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABSetupRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, error)
	encode  func(ERABSetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequestIEValueERABIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABSetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestIEValueERABIEContainerListValueCodec) New(value ERABSetupRequestIEValueERABIEContainerList) (ERABSetupRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABSetupRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABSetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestIEValueERABIEContainerListValueCodec) encodeChanged(value ERABSetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABSetupRequestIEValue].
type ERABSetupRequestIEValueERABIEContainerList []ERABSetupRequestIEValueProtocolIESingleContainer

func BridgeERABSetupRequestIEValueCaptureS1APERABIEContainerList(v *ERABSetupRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupRequestIEValueCompareS1APERABIEContainerList(v *ERABSetupRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverCommandIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, error)
	encode  func(HandoverCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommandIEValueERABIEContainerList, aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandIEValueERABIEContainerListValueCodec) New(value HandoverCommandIEValueERABIEContainerList) (HandoverCommandIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverCommandIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverCommandIEValue].
type HandoverCommandIEValueERABIEContainerList []HandoverCommandIEValueProtocolIESingleContainer

func BridgeHandoverCommandIEValueCaptureS1APERABIEContainerList(v *HandoverCommandIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCommandIEValueCompareS1APERABIEContainerList(v *HandoverCommandIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, error)
	encode  func(PathSwitchRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) New(value PathSwitchRequestIEValueERABIEContainerList) (PathSwitchRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[PathSwitchRequestIEValue].
type PathSwitchRequestIEValueERABIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

// DownlinkS1cdma2000tunnellingIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, error)
	encode  func(DownlinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnellingIEField, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, aper.Snapshot)
	compare func(DownlinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingIEFieldValueCodec) New(value DownlinkS1cdma2000tunnellingIEField) (DownlinkS1cdma2000tunnellingIEFieldAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingIEFieldValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingIEFieldValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingIEFieldValueCodec) encodeChanged(value DownlinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABModifyRequestIEValue]].
type ERABModifyRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequestIEField, error)
	encode  func(ERABModifyRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequestIEField, aper.DecodeState) (ERABModifyRequestIEField, aper.Snapshot)
	compare func(ERABModifyRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestIEFieldValueCodec) New(value ERABModifyRequestIEField) (ERABModifyRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestIEFieldValueCodec) EncodeAPER(value ERABModifyRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestIEFieldValueCodec) encodeBudgetValue(value ERABModifyRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestIEFieldValueCodec) encodeChanged(value ERABModifyRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABSetupRequestIEValue]].
type ERABSetupRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequestIEField, error)
	encode  func(ERABSetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequestIEField, aper.DecodeState) (ERABSetupRequestIEField, aper.Snapshot)
	compare func(ERABSetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestIEFieldValueCodec) New(value ERABSetupRequestIEField) (ERABSetupRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestIEFieldValueCodec) EncodeAPER(value ERABSetupRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestIEFieldValueCodec) encodeBudgetValue(value ERABSetupRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestIEFieldValueCodec) encodeChanged(value ERABSetupRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverCommandIEValue]].
type HandoverCommandIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommandIEField, error)
	encode  func(HandoverCommandIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommandIEField, aper.DecodeState) (HandoverCommandIEField, aper.Snapshot)
	compare func(HandoverCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandIEFieldValueCodec) New(value HandoverCommandIEField) (HandoverCommandIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandIEFieldValueCodec) EncodeAPER(value HandoverCommandIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandIEFieldValueCodec) encodeBudgetValue(value HandoverCommandIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandIEFieldValueCodec) encodeChanged(value HandoverCommandIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[PathSwitchRequestIEValue]].
type PathSwitchRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEField, error)
	encode  func(PathSwitchRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEField, aper.DecodeState) (PathSwitchRequestIEField, aper.Snapshot)
	compare func(PathSwitchRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEFieldValueCodec) New(value PathSwitchRequestIEField) (PathSwitchRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEFieldValueCodec) EncodeAPER(value PathSwitchRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestIEFieldValueCodec) encodeBudgetValue(value PathSwitchRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEFieldValueCodec) encodeChanged(value PathSwitchRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkS1cdma2000tunnellingIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, error)
	encode  func(DownlinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, aper.Snapshot)
	compare func(DownlinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingIEContainerValueCodec) New(value DownlinkS1cdma2000tunnellingIEContainer) (DownlinkS1cdma2000tunnellingIEContainerAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingIEContainerValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingIEContainerValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingIEContainerValueCodec) encodeChanged(value DownlinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABModifyRequestIEValue]].
type ERABModifyRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequestIEContainer, error)
	encode  func(ERABModifyRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequestIEContainer, aper.DecodeState) (ERABModifyRequestIEContainer, aper.Snapshot)
	compare func(ERABModifyRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestIEContainerValueCodec) New(value ERABModifyRequestIEContainer) (ERABModifyRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestIEContainerValueCodec) EncodeAPER(value ERABModifyRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestIEContainerValueCodec) encodeBudgetValue(value ERABModifyRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestIEContainerValueCodec) encodeChanged(value ERABModifyRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABSetupRequestIEValue]].
type ERABSetupRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequestIEContainer, error)
	encode  func(ERABSetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequestIEContainer, aper.DecodeState) (ERABSetupRequestIEContainer, aper.Snapshot)
	compare func(ERABSetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestIEContainerValueCodec) New(value ERABSetupRequestIEContainer) (ERABSetupRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestIEContainerValueCodec) EncodeAPER(value ERABSetupRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestIEContainerValueCodec) encodeBudgetValue(value ERABSetupRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestIEContainerValueCodec) encodeChanged(value ERABSetupRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverCommandIEValue]].
type HandoverCommandIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommandIEContainer, error)
	encode  func(HandoverCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommandIEContainer, aper.DecodeState) (HandoverCommandIEContainer, aper.Snapshot)
	compare func(HandoverCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandIEContainerValueCodec) New(value HandoverCommandIEContainer) (HandoverCommandIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandIEContainerValueCodec) EncodeAPER(value HandoverCommandIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandIEContainerValueCodec) encodeBudgetValue(value HandoverCommandIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandIEContainerValueCodec) encodeChanged(value HandoverCommandIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[PathSwitchRequestIEValue]].
type PathSwitchRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEContainer, error)
	encode  func(PathSwitchRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEContainer, aper.DecodeState) (PathSwitchRequestIEContainer, aper.Snapshot)
	compare func(PathSwitchRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEContainerValueCodec) New(value PathSwitchRequestIEContainer) (PathSwitchRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEContainerValueCodec) EncodeAPER(value PathSwitchRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestIEContainerValueCodec) encodeBudgetValue(value PathSwitchRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEContainerValueCodec) encodeChanged(value PathSwitchRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error)
	encode  func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) New(value DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList []DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModifyRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModifyRequestIEValueProtocolErrorIEContainerList) (ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModifyRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModifyRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABModifyRequestIEValue].
type ERABModifyRequestIEValueProtocolErrorIEContainerList []ERABModifyRequestIEValueProtocolIESingleContainer

func BridgeERABModifyRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABModifyRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABModifyRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyRequestIEValueCompareS1APProtocolErrorIEContainerList(v *ERABModifyRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABModifyRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABSetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) New(value ERABSetupRequestIEValueProtocolErrorIEContainerList) (ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABSetupRequestIEValue].
type ERABSetupRequestIEValueProtocolErrorIEContainerList []ERABSetupRequestIEValueProtocolIESingleContainer

func BridgeERABSetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABSetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupRequestIEValueCompareS1APProtocolErrorIEContainerList(v *ERABSetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverCommandIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverCommandIEValueProtocolErrorIEContainerList) (HandoverCommandIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverCommandIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverCommandIEValue].
type HandoverCommandIEValueProtocolErrorIEContainerList []HandoverCommandIEValueProtocolIESingleContainer

func BridgeHandoverCommandIEValueCaptureS1APProtocolErrorIEContainerList(v *HandoverCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCommandIEValueCompareS1APProtocolErrorIEContainerList(v *HandoverCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(PathSwitchRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) New(value PathSwitchRequestIEValueProtocolErrorIEContainerList) (PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[PathSwitchRequestIEValue].
type PathSwitchRequestIEValueProtocolErrorIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

// DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error)
	encode  func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) New(value DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeChanged(value DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList []DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModifyRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, error)
	encode  func(ERABModifyRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyRequestIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModifyRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyRequestIEValueProtocolIEContainerListValueCodec) New(value ERABModifyRequestIEValueProtocolIEContainerList) (ERABModifyRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModifyRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModifyRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModifyRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABModifyRequestIEValue].
type ERABModifyRequestIEValueProtocolIEContainerList []ERABModifyRequestIEValueProtocolIESingleContainer

func BridgeERABModifyRequestIEValueCaptureS1APProtocolIEContainerList(v *ERABModifyRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABModifyRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyRequestIEValueCompareS1APProtocolIEContainerList(v *ERABModifyRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABModifyRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABSetupRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, error)
	encode  func(ERABSetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABSetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupRequestIEValueProtocolIEContainerListValueCodec) New(value ERABSetupRequestIEValueProtocolIEContainerList) (ERABSetupRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABSetupRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABSetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABSetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABSetupRequestIEValue].
type ERABSetupRequestIEValueProtocolIEContainerList []ERABSetupRequestIEValueProtocolIESingleContainer

func BridgeERABSetupRequestIEValueCaptureS1APProtocolIEContainerList(v *ERABSetupRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupRequestIEValueCompareS1APProtocolIEContainerList(v *ERABSetupRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverCommandIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, error)
	encode  func(HandoverCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCommandIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCommandIEValueProtocolIEContainerListValueCodec) New(value HandoverCommandIEValueProtocolIEContainerList) (HandoverCommandIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCommandIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCommandIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCommandIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCommandIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCommandIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCommandIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverCommandIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCommandIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCommandIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCommandIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverCommandIEValue].
type HandoverCommandIEValueProtocolIEContainerList []HandoverCommandIEValueProtocolIESingleContainer

func BridgeHandoverCommandIEValueCaptureS1APProtocolIEContainerList(v *HandoverCommandIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverCommandIEValueCompareS1APProtocolIEContainerList(v *HandoverCommandIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, error)
	encode  func(PathSwitchRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) New(value PathSwitchRequestIEValueProtocolIEContainerList) (PathSwitchRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[PathSwitchRequestIEValue].
type PathSwitchRequestIEValueProtocolIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

// DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkS1cdma2000tunnellingIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[DownlinkS1cdma2000tunnellingIEValue].
type DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer = DownlinkS1cdma2000tunnellingIEField

func BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(v *DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(v *DownlinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABModifyRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModifyRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABModifyRequestIEValue].
type ERABModifyRequestIEValueProtocolIESingleContainer = ERABModifyRequestIEField

func BridgeERABModifyRequestIEValueCaptureS1APProtocolIESingleContainer(v *ERABModifyRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyRequestIEValueCompareS1APProtocolIESingleContainer(v *ERABModifyRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABSetupRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEValueERABIEContainerListAPERValue) WithoutReplay() ERABSetupRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABSetupRequestIEValue].
type ERABSetupRequestIEValueProtocolIESingleContainer = ERABSetupRequestIEField

func BridgeERABSetupRequestIEValueCaptureS1APProtocolIESingleContainer(v *ERABSetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupRequestIEValueCompareS1APProtocolIESingleContainer(v *ERABSetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// HandoverCommandIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCommandIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverCommandIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverCommandIEValue].
type HandoverCommandIEValueProtocolIESingleContainer = HandoverCommandIEField

func BridgeHandoverCommandIEValueCaptureS1APProtocolIESingleContainer(v *HandoverCommandIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCommandIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverCommandIEValueCompareS1APProtocolIESingleContainer(v *HandoverCommandIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCommandIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueERABIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[PathSwitchRequestIEValue].
type PathSwitchRequestIEValueProtocolIESingleContainer = PathSwitchRequestIEField

// DownlinkS1cdma2000tunnellingIEFieldAPERValue is the concrete APERValue[ProtocolIEField[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkS1cdma2000tunnellingIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEFieldAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABModifyRequestIEValue]].
type ERABModifyRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEFieldAPERValue) WithoutReplay() ERABModifyRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABSetupRequestIEValue]].
type ERABSetupRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEFieldAPERValue) WithoutReplay() ERABSetupRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverCommandIEValue]].
type HandoverCommandIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCommandIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEFieldAPERValue) WithoutReplay() HandoverCommandIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[PathSwitchRequestIEValue]].
type PathSwitchRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEFieldAPERValue) WithoutReplay() PathSwitchRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkS1cdma2000tunnellingIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkS1cdma2000tunnellingIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEContainerAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABModifyRequestIEValue]].
type ERABModifyRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEContainerAPERValue) WithoutReplay() ERABModifyRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABSetupRequestIEValue]].
type ERABSetupRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEContainerAPERValue) WithoutReplay() ERABSetupRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverCommandIEValue]].
type HandoverCommandIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCommandIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEContainerAPERValue) WithoutReplay() HandoverCommandIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[PathSwitchRequestIEValue]].
type PathSwitchRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEContainerAPERValue) WithoutReplay() PathSwitchRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCommandIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverCommandIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[DownlinkS1cdma2000tunnellingIEValue]].
type DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) WithoutReplay() DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABModifyRequestIEValue]].
type ERABModifyRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModifyRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABSetupRequestIEValue]].
type ERABSetupRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABSetupRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCommandIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverCommandIEValue]].
type HandoverCommandIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCommandIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCommandIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCommandIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverCommandIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[PathSwitchRequestIEValue]].
type PathSwitchRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APDownlinkS1cdma2000tunnelling(v *DownlinkS1cdma2000tunnelling, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDownlinkS1cdma2000tunnelling(v *DownlinkS1cdma2000tunnelling, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDownlinkS1cdma2000tunnellingIEValue(v *DownlinkS1cdma2000tunnellingIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowERABSubjecttoDataForwardingList == nil)
				if v.rowERABSubjecttoDataForwardingList != nil {
					s24.BridgeCaptureS1APERABSubjecttoDataForwardingList(v.rowERABSubjecttoDataForwardingList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(83):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HOStatus == nil)
				if v.rowCdma2000HOStatus != nil {
					s00.BridgeCaptureS1APCdma2000HOStatus(v.rowCdma2000HOStatus, s)
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
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s00.BridgeCaptureS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkS1cdma2000tunnellingIEValue) captureSemantics(s aper.SemanticCapture) DownlinkS1cdma2000tunnellingIEValue {
	BridgeCaptureS1APDownlinkS1cdma2000tunnellingIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDownlinkS1cdma2000tunnellingIEValue(v *DownlinkS1cdma2000tunnellingIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowERABSubjecttoDataForwardingList == nil)
				if v.rowERABSubjecttoDataForwardingList != nil {
					s24.BridgeCompareS1APERABSubjecttoDataForwardingList(v.rowERABSubjecttoDataForwardingList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(83):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HOStatus == nil)
				if v.rowCdma2000HOStatus != nil {
					s02.BridgeCompareS1APCdma2000HOStatus(v.rowCdma2000HOStatus, s)
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
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s02.BridgeCompareS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkS1cdma2000tunnellingIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDownlinkS1cdma2000tunnellingIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABModifyRequest(v *ERABModifyRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyRequest(v *ERABModifyRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModifyRequestIEValue(v *ERABModifyRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(30):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedListBearerModReq == nil)
				if v.rowERABToBeModifiedListBearerModReq != nil {
					s25.BridgeCaptureS1APERABToBeModifiedListBearerModReq(v.rowERABToBeModifiedListBearerModReq, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(268):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageRequest == nil)
				if v.rowSecondaryRATDataUsageRequest != nil {
					s00.BridgeCaptureS1APSecondaryRATDataUsageRequest(v.rowSecondaryRATDataUsageRequest, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyRequestIEValue) captureSemantics(s aper.SemanticCapture) ERABModifyRequestIEValue {
	BridgeCaptureS1APERABModifyRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModifyRequestIEValue(v *ERABModifyRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(30):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedListBearerModReq == nil)
				if v.rowERABToBeModifiedListBearerModReq != nil {
					s25.BridgeCompareS1APERABToBeModifiedListBearerModReq(v.rowERABToBeModifiedListBearerModReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(268):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageRequest == nil)
				if v.rowSecondaryRATDataUsageRequest != nil {
					s06.BridgeCompareS1APSecondaryRATDataUsageRequest(v.rowSecondaryRATDataUsageRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModifyRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABSetupRequest(v *ERABSetupRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupRequest(v *ERABSetupRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupRequestIEValue(v *ERABSetupRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(16):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListBearerSUReq == nil)
				if v.rowERABToBeSetupListBearerSUReq != nil {
					s29.BridgeCaptureS1APERABToBeSetupListBearerSUReq(v.rowERABToBeSetupListBearerSUReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupRequestIEValue) captureSemantics(s aper.SemanticCapture) ERABSetupRequestIEValue {
	BridgeCaptureS1APERABSetupRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABSetupRequestIEValue(v *ERABSetupRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(16):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListBearerSUReq == nil)
				if v.rowERABToBeSetupListBearerSUReq != nil {
					s29.BridgeCompareS1APERABToBeSetupListBearerSUReq(v.rowERABToBeSetupListBearerSUReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABSetupRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeModifiedListBearerModIndComplete(v *ERABToBeModifiedListBearerModIndComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABToBeModifiedListBearerModInd(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeModifiedListBearerModIndComplete(v *ERABToBeModifiedListBearerModIndComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABToBeModifiedListBearerModInd(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeModifiedListBearerModReqComplete(v *ERABToBeModifiedListBearerModReqComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABToBeModifiedListBearerModReq(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeModifiedListBearerModReqComplete(v *ERABToBeModifiedListBearerModReqComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABToBeModifiedListBearerModReq(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupListBearerSUReqComplete(v *ERABToBeSetupListBearerSUReqComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCaptureS1APERABToBeSetupListBearerSUReq(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupListBearerSUReqComplete(v *ERABToBeSetupListBearerSUReqComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCompareS1APERABToBeSetupListBearerSUReq(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupListCtxtSUReqComplete(v *ERABToBeSetupListCtxtSUReqComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCaptureS1APERABToBeSetupListCtxtSUReq(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupListCtxtSUReqComplete(v *ERABToBeSetupListCtxtSUReqComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCompareS1APERABToBeSetupListCtxtSUReq(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSetupListHOReqComplete(v *ERABToBeSetupListHOReqComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APERABToBeSetupListHOReq(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSetupListHOReqComplete(v *ERABToBeSetupListHOReqComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APERABToBeSetupListHOReq(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSwitchedDLListComplete(v *ERABToBeSwitchedDLListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APERABToBeSwitchedDLList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSwitchedDLListComplete(v *ERABToBeSwitchedDLListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APERABToBeSwitchedDLList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverCommand(v *HandoverCommand, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCommandIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverCommand(v *HandoverCommand, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverCommandIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverCommandIEValue(v *HandoverCommandIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s00.BridgeCaptureS1APHandoverType(v.rowHandoverType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(135):
			{
				f := s.Begin()
				s.Bool(v.rowNASSecurityParametersfromEUTRAN == nil)
				if v.rowNASSecurityParametersfromEUTRAN != nil {
					s00.BridgeCaptureS1APNASSecurityParametersfromEUTRAN(v.rowNASSecurityParametersfromEUTRAN, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowERABSubjecttoDataForwardingList == nil)
				if v.rowERABSubjecttoDataForwardingList != nil {
					s24.BridgeCaptureS1APERABSubjecttoDataForwardingList(v.rowERABSubjecttoDataForwardingList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowERABtoReleaseListHOCmd == nil)
				if v.rowERABtoReleaseListHOCmd != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABtoReleaseListHOCmd, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(123):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainer == nil)
				if v.rowTargetToSourceTransparentContainer != nil {
					s00.BridgeCaptureS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(139):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainerSecondary == nil)
				if v.rowTargetToSourceTransparentContainerSecondary != nil {
					s00.BridgeCaptureS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainerSecondary, s)
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
func (v HandoverCommandIEValue) captureSemantics(s aper.SemanticCapture) HandoverCommandIEValue {
	BridgeCaptureS1APHandoverCommandIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverCommandIEValue(v *HandoverCommandIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s02.BridgeCompareS1APHandoverType(v.rowHandoverType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(135):
			{
				f := s.Begin()
				s.Bool(v.rowNASSecurityParametersfromEUTRAN == nil)
				if v.rowNASSecurityParametersfromEUTRAN != nil {
					s02.BridgeCompareS1APNASSecurityParametersfromEUTRAN(v.rowNASSecurityParametersfromEUTRAN, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowERABSubjecttoDataForwardingList == nil)
				if v.rowERABSubjecttoDataForwardingList != nil {
					s24.BridgeCompareS1APERABSubjecttoDataForwardingList(v.rowERABSubjecttoDataForwardingList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowERABtoReleaseListHOCmd == nil)
				if v.rowERABtoReleaseListHOCmd != nil {
					s24.BridgeCompareS1APERABList(v.rowERABtoReleaseListHOCmd, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(123):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainer == nil)
				if v.rowTargetToSourceTransparentContainer != nil {
					s07.BridgeCompareS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(139):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainerSecondary == nil)
				if v.rowTargetToSourceTransparentContainerSecondary != nil {
					s07.BridgeCompareS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainerSecondary, s)
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
func (v HandoverCommandIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverCommandIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APPathSwitchRequestIEValue(v *PathSwitchRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLList == nil)
				if v.rowERABToBeSwitchedDLList != nil {
					s30.BridgeCaptureS1APERABToBeSwitchedDLList(v.rowERABToBeSwitchedDLList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(88):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEUES1APID == nil)
				if v.rowSourceMMEUES1APID != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowSourceMMEUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(127):
			{
				f := s.Begin()
				s.Bool(v.rowCSGId == nil)
				if v.rowCSGId != nil {
					s00.BridgeCaptureS1APCSGId(v.rowCSGId, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s00.BridgeCaptureS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(157):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEGUMMEI == nil)
				if v.rowSourceMMEGUMMEI != nil {
					s18.BridgeCaptureS1APGUMMEI(v.rowSourceMMEGUMMEI, s)
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
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s00.BridgeCaptureS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s00.BridgeCaptureS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s20.BridgeCaptureS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestIEValue) captureSemantics(s aper.SemanticCapture) PathSwitchRequestIEValue {
	BridgeCaptureS1APPathSwitchRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPathSwitchRequestIEValue(v *PathSwitchRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLList == nil)
				if v.rowERABToBeSwitchedDLList != nil {
					s30.BridgeCompareS1APERABToBeSwitchedDLList(v.rowERABToBeSwitchedDLList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(88):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEUES1APID == nil)
				if v.rowSourceMMEUES1APID != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowSourceMMEUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(127):
			{
				f := s.Begin()
				s.Bool(v.rowCSGId == nil)
				if v.rowCSGId != nil {
					s02.BridgeCompareS1APCSGId(v.rowCSGId, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s02.BridgeCompareS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(157):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEGUMMEI == nil)
				if v.rowSourceMMEGUMMEI != nil {
					s18.BridgeCompareS1APGUMMEI(v.rowSourceMMEGUMMEI, s)
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
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s02.BridgeCompareS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s06.BridgeCompareS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s20.BridgeCompareS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPathSwitchRequestIEValue(&v, &s)
	return s
}

// HandoverCommand represents the ASN.1 type HandoverCommand (SEQUENCE).
type HandoverCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      HandoverCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                       `asn1:"-" json:"-"`
	extCount         int64                      `asn1:"-" json:"-"`
	extPresent       []bool                     `asn1:"-" json:"-"`
	extData          [][]byte                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABSetupRequest represents the ASN.1 type E-RABSetupRequest (SEQUENCE).
type ERABSetupRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ERABSetupRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABModifyRequest represents the ASN.1 type E-RABModifyRequest (SEQUENCE).
type ERABModifyRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ERABModifyRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                         `asn1:"-" json:"-"`
	extCount         int64                        `asn1:"-" json:"-"`
	extPresent       []bool                       `asn1:"-" json:"-"`
	extData          [][]byte                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// DownlinkS1cdma2000tunnelling represents the ASN.1 type DownlinkS1cdma2000tunnelling (SEQUENCE).
type DownlinkS1cdma2000tunnelling struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      DownlinkS1cdma2000tunnellingIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes HandoverCommand to APER format.
func (v *HandoverCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
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
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes HandoverCommand from APER format.
func (v *HandoverCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverCommand with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCommand")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverCommand")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCommand{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(HandoverCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem HandoverCommandIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPERERABSubjecttoDataForwardingList encodes a ERABSubjecttoDataForwardingList list to APER.
func BridgeMarshalAPERERABSubjecttoDataForwardingList(list s39.ERABSubjecttoDataForwardingListComplete) ([]byte, error) {
	return s39.BridgeERABSubjecttoDataForwardingListCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERERABSubjecttoDataForwardingList decodes a ERABSubjecttoDataForwardingList list from APER.
func BridgeUnmarshalAPERERABSubjecttoDataForwardingList(data []byte) (s39.ERABSubjecttoDataForwardingListComplete, error) {
	var value s39.ERABSubjecttoDataForwardingListComplete
	if err := s39.BridgeERABSubjecttoDataForwardingListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// ERABToBeSetupListHOReqComplete carries a complete ERABToBeSetupListHOReq encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeSetupListHOReqComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s29.ERABToBeSetupListHOReq
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeSetupListHOReqComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABToBeSetupListHOReqTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeSetupListHOReq from APER format.
func (v *ERABToBeSetupListHOReqComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupListHOReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupListHOReqComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
	}
	value, err := BridgeUnmarshalAPERERABToBeSetupListHOReqFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupListHOReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeSetupListHOReq encodes a ERABToBeSetupListHOReq list to APER.
func BridgeMarshalAPERERABToBeSetupListHOReq(list ERABToBeSetupListHOReqComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeSetupListHOReq decodes a ERABToBeSetupListHOReq list from APER.
func BridgeUnmarshalAPERERABToBeSetupListHOReq(data []byte) (ERABToBeSetupListHOReqComplete, error) {
	var value ERABToBeSetupListHOReqComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListHOReqFrom decodes a ERABToBeSetupListHOReq list from bb.
func BridgeUnmarshalAPERERABToBeSetupListHOReqFrom(bb *aper.BitBuffer) (s29.ERABToBeSetupListHOReq, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s30.BridgeAsn1cAPERERABToBeSetupListHOReqListValue
	if err := BridgeUnmarshalAPERERABToBeSetupListHOReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeSetupListHOReqInto(v *s30.BridgeAsn1cAPERERABToBeSetupListHOReqListValue, bb *aper.BitBuffer) error {
	v.Value = make(s29.ERABToBeSetupListHOReq, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s29.ERABToBeSetupItemHOReqIEValueProtocolIESingleContainer
			if err := s29.BridgeERABToBeSetupItemHOReqIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ERABToBeSwitchedDLListComplete carries a complete ERABToBeSwitchedDLList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeSwitchedDLListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s30.ERABToBeSwitchedDLList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeSwitchedDLListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABToBeSwitchedDLListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeSwitchedDLList from APER format.
func (v *ERABToBeSwitchedDLListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSwitchedDLList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSwitchedDLListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
	}
	value, err := BridgeUnmarshalAPERERABToBeSwitchedDLListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedDLList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// UnmarshalAPERERABToBeSwitchedDLListFrom decodes a ERABToBeSwitchedDLList list from bb.
func BridgeUnmarshalAPERERABToBeSwitchedDLListFrom(bb *aper.BitBuffer) (s30.ERABToBeSwitchedDLList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s30.BridgeAsn1cAPERERABToBeSwitchedDLListListValue
	if err := BridgeUnmarshalAPERERABToBeSwitchedDLListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeSwitchedDLListInto(v *s30.BridgeAsn1cAPERERABToBeSwitchedDLListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s30.ERABToBeSwitchedDLList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s30.ERABToBeSwitchedDLItemIEValueProtocolIESingleContainer
			if err := s30.BridgeERABToBeSwitchedDLItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ERABSetupRequest to APER format.
func (v *ERABSetupRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSetupRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
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
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ERABSetupRequest from APER format.
func (v *ERABSetupRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABSetupRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ERABSetupRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ERABSetupRequestIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeSetupListBearerSUReqComplete carries a complete ERABToBeSetupListBearerSUReq encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeSetupListBearerSUReqComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s29.ERABToBeSetupListBearerSUReq
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABToBeSetupListBearerSUReqTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeSetupListBearerSUReq from APER format.
func (v *ERABToBeSetupListBearerSUReqComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupListBearerSUReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupListBearerSUReqComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListBearerSUReq")
	}
	value, err := BridgeUnmarshalAPERERABToBeSetupListBearerSUReqFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListBearerSUReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupListBearerSUReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListBearerSUReq")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeSetupListBearerSUReq encodes a ERABToBeSetupListBearerSUReq list to APER.
func BridgeMarshalAPERERABToBeSetupListBearerSUReq(list ERABToBeSetupListBearerSUReqComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeSetupListBearerSUReq decodes a ERABToBeSetupListBearerSUReq list from APER.
func BridgeUnmarshalAPERERABToBeSetupListBearerSUReq(data []byte) (ERABToBeSetupListBearerSUReqComplete, error) {
	var value ERABToBeSetupListBearerSUReqComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListBearerSUReqFrom decodes a ERABToBeSetupListBearerSUReq list from bb.
func BridgeUnmarshalAPERERABToBeSetupListBearerSUReqFrom(bb *aper.BitBuffer) (s29.ERABToBeSetupListBearerSUReq, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s29.BridgeAsn1cAPERERABToBeSetupListBearerSUReqListValue
	if err := BridgeUnmarshalAPERERABToBeSetupListBearerSUReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeSetupListBearerSUReqInto(v *s29.BridgeAsn1cAPERERABToBeSetupListBearerSUReqListValue, bb *aper.BitBuffer) error {
	v.Value = make(s29.ERABToBeSetupListBearerSUReq, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s29.ERABToBeSetupItemBearerSUReqIEValueProtocolIESingleContainer
			if err := s29.BridgeERABToBeSetupItemBearerSUReqIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ERABModifyRequest to APER format.
func (v *ERABModifyRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModifyRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
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
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ERABModifyRequest from APER format.
func (v *ERABModifyRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModifyRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModifyRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABModifyRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ERABModifyRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ERABModifyRequestIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeModifiedListBearerModReqComplete carries a complete ERABToBeModifiedListBearerModReq encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeModifiedListBearerModReqComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s25.ERABToBeModifiedListBearerModReq
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABToBeModifiedListBearerModReqTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeModifiedListBearerModReq from APER format.
func (v *ERABToBeModifiedListBearerModReqComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeModifiedListBearerModReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeModifiedListBearerModReqComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModReq")
	}
	value, err := BridgeUnmarshalAPERERABToBeModifiedListBearerModReqFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedListBearerModReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModReq")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeModifiedListBearerModReq encodes a ERABToBeModifiedListBearerModReq list to APER.
func BridgeMarshalAPERERABToBeModifiedListBearerModReq(list ERABToBeModifiedListBearerModReqComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeModifiedListBearerModReq decodes a ERABToBeModifiedListBearerModReq list from APER.
func BridgeUnmarshalAPERERABToBeModifiedListBearerModReq(data []byte) (ERABToBeModifiedListBearerModReqComplete, error) {
	var value ERABToBeModifiedListBearerModReqComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeModifiedListBearerModReqFrom decodes a ERABToBeModifiedListBearerModReq list from bb.
func BridgeUnmarshalAPERERABToBeModifiedListBearerModReqFrom(bb *aper.BitBuffer) (s25.ERABToBeModifiedListBearerModReq, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue
	if err := BridgeUnmarshalAPERERABToBeModifiedListBearerModReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeModifiedListBearerModReqInto(v *s25.BridgeAsn1cAPERERABToBeModifiedListBearerModReqListValue, bb *aper.BitBuffer) error {
	v.Value = make(s25.ERABToBeModifiedListBearerModReq, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s25.ERABToBeModifiedItemBearerModReqIEValueProtocolIESingleContainer
			if err := s25.BridgeERABToBeModifiedItemBearerModReqIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ERABToBeSetupListCtxtSUReqComplete carries a complete ERABToBeSetupListCtxtSUReq encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeSetupListCtxtSUReqComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s29.ERABToBeSetupListCtxtSUReq
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABToBeSetupListCtxtSUReqTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeSetupListCtxtSUReq from APER format.
func (v *ERABToBeSetupListCtxtSUReqComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSetupListCtxtSUReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSetupListCtxtSUReqComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
	}
	value, err := BridgeUnmarshalAPERERABToBeSetupListCtxtSUReqFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSetupListCtxtSUReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeSetupListCtxtSUReq encodes a ERABToBeSetupListCtxtSUReq list to APER.
func BridgeMarshalAPERERABToBeSetupListCtxtSUReq(list ERABToBeSetupListCtxtSUReqComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeSetupListCtxtSUReq decodes a ERABToBeSetupListCtxtSUReq list from APER.
func BridgeUnmarshalAPERERABToBeSetupListCtxtSUReq(data []byte) (ERABToBeSetupListCtxtSUReqComplete, error) {
	var value ERABToBeSetupListCtxtSUReqComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListCtxtSUReqFrom decodes a ERABToBeSetupListCtxtSUReq list from bb.
func BridgeUnmarshalAPERERABToBeSetupListCtxtSUReqFrom(bb *aper.BitBuffer) (s29.ERABToBeSetupListCtxtSUReq, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s29.BridgeAsn1cAPERERABToBeSetupListCtxtSUReqListValue
	if err := BridgeUnmarshalAPERERABToBeSetupListCtxtSUReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeSetupListCtxtSUReqInto(v *s29.BridgeAsn1cAPERERABToBeSetupListCtxtSUReqListValue, bb *aper.BitBuffer) error {
	v.Value = make(s29.ERABToBeSetupListCtxtSUReq, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s29.ERABToBeSetupItemCtxtSUReqIEValueProtocolIESingleContainer
			if err := s29.BridgeERABToBeSetupItemCtxtSUReqIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes DownlinkS1cdma2000tunnelling to APER format.
func (v *DownlinkS1cdma2000tunnelling) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
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
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes DownlinkS1cdma2000tunnelling from APER format.
func (v *DownlinkS1cdma2000tunnelling) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DownlinkS1cdma2000tunnelling with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DownlinkS1cdma2000tunnelling) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkS1cdma2000tunnelling")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkS1cdma2000tunnelling")
	}
	padding, err := aper.CaptureFinalBits(bb, "DownlinkS1cdma2000tunnelling")
	if err != nil {
		return runtime.WrapDecodePath(err, "DownlinkS1cdma2000tunnelling")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DownlinkS1cdma2000tunnelling) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkS1cdma2000tunnelling{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(DownlinkS1cdma2000tunnellingIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem DownlinkS1cdma2000tunnellingIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABToBeModifiedListBearerModIndComplete carries a complete ERABToBeModifiedListBearerModInd encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeModifiedListBearerModIndComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.ERABToBeModifiedListBearerModInd
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABToBeModifiedListBearerModIndTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeModifiedListBearerModInd from APER format.
func (v *ERABToBeModifiedListBearerModIndComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeModifiedListBearerModInd with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeModifiedListBearerModIndComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
	}
	value, err := BridgeUnmarshalAPERERABToBeModifiedListBearerModIndFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedListBearerModInd")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeModifiedListBearerModInd encodes a ERABToBeModifiedListBearerModInd list to APER.
func BridgeMarshalAPERERABToBeModifiedListBearerModInd(list ERABToBeModifiedListBearerModIndComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeModifiedListBearerModInd decodes a ERABToBeModifiedListBearerModInd list from APER.
func BridgeUnmarshalAPERERABToBeModifiedListBearerModInd(data []byte) (ERABToBeModifiedListBearerModIndComplete, error) {
	var value ERABToBeModifiedListBearerModIndComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeModifiedListBearerModIndFrom decodes a ERABToBeModifiedListBearerModInd list from bb.
func BridgeUnmarshalAPERERABToBeModifiedListBearerModIndFrom(bb *aper.BitBuffer) (s17.ERABToBeModifiedListBearerModInd, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue
	if err := BridgeUnmarshalAPERERABToBeModifiedListBearerModIndInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeModifiedListBearerModIndInto(v *s21.BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue, bb *aper.BitBuffer) error {
	v.Value = make(s17.ERABToBeModifiedListBearerModInd, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer
			if err := s17.BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DownlinkS1cdma2000tunnelling) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DownlinkS1cdma2000tunnelling", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DownlinkS1cdma2000tunnelling", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DownlinkS1cdma2000tunnelling) WithoutReplay() DownlinkS1cdma2000tunnelling {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DownlinkS1cdma2000tunnelling
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyRequest) WithoutReplay() ERABModifyRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupRequest) WithoutReplay() ERABSetupRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeModifiedListBearerModIndComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeModifiedListBearerModIndComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeModifiedListBearerModIndComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeModifiedListBearerModIndComplete) WithoutReplay() ERABToBeModifiedListBearerModIndComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeModifiedListBearerModIndComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeModifiedListBearerModReqComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeModifiedListBearerModReqComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeModifiedListBearerModReqComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeModifiedListBearerModReqComplete) WithoutReplay() ERABToBeModifiedListBearerModReqComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeModifiedListBearerModReqComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSetupListBearerSUReqComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupListBearerSUReqComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupListBearerSUReqComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupListBearerSUReqComplete) WithoutReplay() ERABToBeSetupListBearerSUReqComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupListBearerSUReqComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSetupListCtxtSUReqComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupListCtxtSUReqComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupListCtxtSUReqComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupListCtxtSUReqComplete) WithoutReplay() ERABToBeSetupListCtxtSUReqComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupListCtxtSUReqComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSetupListHOReqComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSetupListHOReqComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSetupListHOReqComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSetupListHOReqComplete) WithoutReplay() ERABToBeSetupListHOReqComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSetupListHOReqComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSwitchedDLListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSwitchedDLListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSwitchedDLListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSwitchedDLListComplete) WithoutReplay() ERABToBeSwitchedDLListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSwitchedDLListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverCommand", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverCommand", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverCommand) WithoutReplay() HandoverCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverCommand
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *DownlinkS1cdma2000tunnelling) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DownlinkS1cdma2000tunnelling) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DownlinkS1cdma2000tunnelling) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModifyRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModifyRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModifyRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABSetupRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSetupRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSetupRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *DownlinkS1cdma2000tunnelling) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DownlinkS1cdma2000tunnelling")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDownlinkS1cdma2000tunnelling(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DownlinkS1cdma2000tunnelling")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDownlinkS1cdma2000tunnelling(v, &s)
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
func (v *DownlinkS1cdma2000tunnelling) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DownlinkS1cdma2000tunnelling) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABModifyRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyRequest")
}
func (v *ERABModifyRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyRequest")
}
func (v *ERABModifyRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyRequest(v, &s)
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
func (v *ERABModifyRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSetupRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupRequest")
}
func (v *ERABSetupRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupRequest")
}
func (v *ERABSetupRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupRequest(v, &s)
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
func (v *ERABSetupRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeModifiedListBearerModIndComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeModifiedListBearerModIndComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedListBearerModIndComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeModifiedListBearerModIndComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeModifiedListBearerModIndComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeModifiedListBearerModIndComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeModifiedListBearerModIndComplete")
}
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeModifiedListBearerModIndComplete")
}
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeModifiedListBearerModIndComplete(v, &s)
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
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeModifiedListBearerModIndComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABToBeModifiedListBearerModIndTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeModifiedListBearerModReqComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeModifiedListBearerModReqComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedListBearerModReqComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeModifiedListBearerModReqComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeModifiedListBearerModReqComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeModifiedListBearerModReqComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeModifiedListBearerModReqComplete")
}
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeModifiedListBearerModReqComplete")
}
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeModifiedListBearerModReqComplete(v, &s)
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
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeModifiedListBearerModReqComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABToBeModifiedListBearerModReqTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSetupListBearerSUReqComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupListBearerSUReqComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListBearerSUReqComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupListBearerSUReqComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupListBearerSUReqComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupListBearerSUReqComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupListBearerSUReqComplete")
}
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupListBearerSUReqComplete")
}
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupListBearerSUReqComplete(v, &s)
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
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupListBearerSUReqComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABToBeSetupListBearerSUReqTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSetupListCtxtSUReqComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupListCtxtSUReqComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListCtxtSUReqComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupListCtxtSUReqComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupListCtxtSUReqComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupListCtxtSUReqComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupListCtxtSUReqComplete")
}
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupListCtxtSUReqComplete")
}
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupListCtxtSUReqComplete(v, &s)
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
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupListCtxtSUReqComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABToBeSetupListCtxtSUReqTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSetupListHOReqComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSetupListHOReqComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSetupListHOReqComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListHOReqComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSetupListHOReqComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSetupListHOReqComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSetupListHOReqComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSetupListHOReqComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSetupListHOReqComplete")
}
func (v *ERABToBeSetupListHOReqComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSetupListHOReqComplete")
}
func (v *ERABToBeSetupListHOReqComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSetupListHOReqComplete(v, &s)
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
func (v *ERABToBeSetupListHOReqComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSetupListHOReqComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABToBeSetupListHOReqTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSwitchedDLListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSwitchedDLListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSwitchedDLListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedDLListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSwitchedDLListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSwitchedDLListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSwitchedDLListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSwitchedDLListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSwitchedDLListComplete")
}
func (v *ERABToBeSwitchedDLListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSwitchedDLListComplete")
}
func (v *ERABToBeSwitchedDLListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSwitchedDLListComplete(v, &s)
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
func (v *ERABToBeSwitchedDLListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSwitchedDLListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABToBeSwitchedDLListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverCommand")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverCommand) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverCommand")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverCommand(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverCommand")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverCommand")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverCommand")
}
func (v *HandoverCommand) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverCommand")
}
func (v *HandoverCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverCommand(v, &s)
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
func (v *HandoverCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DownlinkS1cdma2000tunnelling) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DownlinkS1cdma2000tunnelling")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DownlinkS1cdma2000tunnelling
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDownlinkS1cdma2000tunnelling(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DownlinkS1cdma2000tunnelling{}
		return report, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DownlinkS1cdma2000tunnelling")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyRequest{}
		return report, aper.OperationError(err, "ERABModifyRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupRequest{}
		return report, aper.OperationError(err, "ERABSetupRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeModifiedListBearerModIndComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedListBearerModIndComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeModifiedListBearerModIndComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeModifiedListBearerModIndComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeModifiedListBearerModIndComplete{}
		return report, aper.OperationError(err, "ERABToBeModifiedListBearerModIndComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeModifiedListBearerModIndComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeModifiedListBearerModReqComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedListBearerModReqComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeModifiedListBearerModReqComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeModifiedListBearerModReqComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeModifiedListBearerModReqComplete{}
		return report, aper.OperationError(err, "ERABToBeModifiedListBearerModReqComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeModifiedListBearerModReqComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSetupListBearerSUReqComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListBearerSUReqComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupListBearerSUReqComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupListBearerSUReqComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupListBearerSUReqComplete{}
		return report, aper.OperationError(err, "ERABToBeSetupListBearerSUReqComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupListBearerSUReqComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSetupListCtxtSUReqComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListCtxtSUReqComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupListCtxtSUReqComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupListCtxtSUReqComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupListCtxtSUReqComplete{}
		return report, aper.OperationError(err, "ERABToBeSetupListCtxtSUReqComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupListCtxtSUReqComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSetupListHOReqComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSetupListHOReqComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSetupListHOReqComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSetupListHOReqComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSetupListHOReqComplete{}
		return report, aper.OperationError(err, "ERABToBeSetupListHOReqComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSetupListHOReqComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSwitchedDLListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedDLListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSwitchedDLListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSwitchedDLListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSwitchedDLListComplete{}
		return report, aper.OperationError(err, "ERABToBeSwitchedDLListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSwitchedDLListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverCommand")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverCommand
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverCommand{}
		return report, aper.OperationError(err, "HandoverCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverCommand")
}

// MarshalAPERERABSubjecttoDataForwardingList encodes a complete named list.
func MarshalAPERERABSubjecttoDataForwardingList(v s39.ERABSubjecttoDataForwardingListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeSetupListHOReq encodes a complete named list.
func MarshalAPERERABToBeSetupListHOReq(v ERABToBeSetupListHOReqComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeSwitchedDLList encodes a complete named list.
func MarshalAPERERABToBeSwitchedDLList(v ERABToBeSwitchedDLListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeSetupListBearerSUReq encodes a complete named list.
func MarshalAPERERABToBeSetupListBearerSUReq(v ERABToBeSetupListBearerSUReqComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeModifiedListBearerModReq encodes a complete named list.
func MarshalAPERERABToBeModifiedListBearerModReq(v ERABToBeModifiedListBearerModReqComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeSetupListCtxtSUReq encodes a complete named list.
func MarshalAPERERABToBeSetupListCtxtSUReq(v ERABToBeSetupListCtxtSUReqComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeModifiedListBearerModInd encodes a complete named list.
func MarshalAPERERABToBeModifiedListBearerModInd(v ERABToBeModifiedListBearerModIndComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABSubjecttoDataForwardingList decodes a complete named list.
func UnmarshalAPERERABSubjecttoDataForwardingList(data []byte, options ...aper.DecodeOption) (s39.ERABSubjecttoDataForwardingListComplete, aper.DecodeReport, error) {
	var v s39.ERABSubjecttoDataForwardingListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeSetupListHOReq decodes a complete named list.
func UnmarshalAPERERABToBeSetupListHOReq(data []byte, options ...aper.DecodeOption) (ERABToBeSetupListHOReqComplete, aper.DecodeReport, error) {
	var v ERABToBeSetupListHOReqComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeSetupListBearerSUReq decodes a complete named list.
func UnmarshalAPERERABToBeSetupListBearerSUReq(data []byte, options ...aper.DecodeOption) (ERABToBeSetupListBearerSUReqComplete, aper.DecodeReport, error) {
	var v ERABToBeSetupListBearerSUReqComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeModifiedListBearerModReq decodes a complete named list.
func UnmarshalAPERERABToBeModifiedListBearerModReq(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedListBearerModReqComplete, aper.DecodeReport, error) {
	var v ERABToBeModifiedListBearerModReqComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeSetupListCtxtSUReq decodes a complete named list.
func UnmarshalAPERERABToBeSetupListCtxtSUReq(data []byte, options ...aper.DecodeOption) (ERABToBeSetupListCtxtSUReqComplete, aper.DecodeReport, error) {
	var v ERABToBeSetupListCtxtSUReqComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeModifiedListBearerModInd decodes a complete named list.
func UnmarshalAPERERABToBeModifiedListBearerModInd(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedListBearerModIndComplete, aper.DecodeReport, error) {
	var v ERABToBeModifiedListBearerModIndComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type DownlinkS1cdma2000tunnellingIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABSubjecttoDataForwardingList *s16.ERABSubjecttoDataForwardingList
	rowCdma2000HOStatus                *s00.Cdma2000HOStatus
	rowCdma2000RATType                 *s00.Cdma2000RATType
	rowCdma2000PDU                     *s00.Cdma2000PDU
}

func (v DownlinkS1cdma2000tunnellingIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(12):
		return v.rowERABSubjecttoDataForwardingList != nil
	case s00.ProtocolIEID(83):
		return v.rowCdma2000HOStatus != nil
	case s00.ProtocolIEID(71):
		return v.rowCdma2000RATType != nil
	case s00.ProtocolIEID(70):
		return v.rowCdma2000PDU != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DownlinkS1cdma2000tunnellingIEValue and reports whether the opaque alternative is selected.
func (v *DownlinkS1cdma2000tunnellingIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DownlinkS1cdma2000tunnellingIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs"}}
}
func (DownlinkS1cdma2000tunnellingIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(12):
		return aper.UnknownSelector
	case s00.ProtocolIEID(83):
		return aper.UnknownSelector
	case s00.ProtocolIEID(71):
		return aper.UnknownSelector
	case s00.ProtocolIEID(70):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABSubjecttoDataForwardingList returns the selected ERABSubjecttoDataForwardingList value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsERABSubjecttoDataForwardingList() (*s16.ERABSubjecttoDataForwardingList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(12) || v.rowERABSubjecttoDataForwardingList == nil {
		return nil, false
	}
	return v.rowERABSubjecttoDataForwardingList, true
}

// AsCdma2000HOStatus returns the selected Cdma2000HOStatus value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsCdma2000HOStatus() (*s00.Cdma2000HOStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(83) || v.rowCdma2000HOStatus == nil {
		return nil, false
	}
	return v.rowCdma2000HOStatus, true
}

// AsCdma2000RATType returns the selected Cdma2000RATType value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsCdma2000RATType() (*s00.Cdma2000RATType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(71) || v.rowCdma2000RATType == nil {
		return nil, false
	}
	return v.rowCdma2000RATType, true
}

// AsCdma2000PDU returns the selected Cdma2000PDU value of DownlinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *DownlinkS1cdma2000tunnellingIEValue) AsCdma2000PDU() (*s00.Cdma2000PDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(70) || v.rowCdma2000PDU == nil {
		return nil, false
	}
	return v.rowCdma2000PDU, true
}
func (v DownlinkS1cdma2000tunnellingIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DownlinkS1cdma2000tunnellingIEValue, error) {
	out := DownlinkS1cdma2000tunnellingIEValue{id: id}
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
	case s00.ProtocolIEID(12):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABSubjecttoDataForwardingListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABSubjecttoDataForwardingList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABSubjecttoDataForwardingList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(83):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Cdma2000HOStatus"})
		value := s00.Cdma2000HOStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000HOStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCdma2000HOStatus = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v DownlinkS1cdma2000tunnellingIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v DownlinkS1cdma2000tunnellingIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(12):
		if v.rowERABSubjecttoDataForwardingList == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-E-RABSubjecttoDataForwardingList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABSubjecttoDataForwardingListComplete{Value: *v.rowERABSubjecttoDataForwardingList}
		candidate, err := s39.BridgeERABSubjecttoDataForwardingListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(83):
		if v.rowCdma2000HOStatus == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-cdma2000HOStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCdma2000HOStatus), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(71):
		if v.rowCdma2000RATType == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-cdma2000RATType:")
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
	case s00.ProtocolIEID(70):
		if v.rowCdma2000PDU == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkS1cdma2000tunnellingIEs.id-cdma2000PDU:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DownlinkS1cdma2000tunnellingIEValue:", v.id)
	}
}

type ERABModifyRequestIEValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowMMEUES1APID                      *s00.MMEUES1APID
	rowENBUES1APID                      *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate        *s35.UEAggregateMaximumBitrate
	rowERABToBeModifiedListBearerModReq *s25.ERABToBeModifiedListBearerModReq
	rowSecondaryRATDataUsageRequest     *s00.SecondaryRATDataUsageRequest
}

func (v ERABModifyRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(30):
		return v.rowERABToBeModifiedListBearerModReq != nil
	case s00.ProtocolIEID(268):
		return v.rowSecondaryRATDataUsageRequest != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABModifyRequestIEValue and reports whether the opaque alternative is selected.
func (v *ERABModifyRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModifyRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs"}}
}
func (ERABModifyRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(30):
		return aper.UnknownSelector
	case s00.ProtocolIEID(268):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABModifyRequestIEValue and reports whether that alternative is active.
func (v *ERABModifyRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABModifyRequestIEValue and reports whether that alternative is active.
func (v *ERABModifyRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of ERABModifyRequestIEValue and reports whether that alternative is active.
func (v *ERABModifyRequestIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeModifiedListBearerModReq returns the selected ERABToBeModifiedListBearerModReq value of ERABModifyRequestIEValue and reports whether that alternative is active.
func (v *ERABModifyRequestIEValue) AsERABToBeModifiedListBearerModReq() (*s25.ERABToBeModifiedListBearerModReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(30) || v.rowERABToBeModifiedListBearerModReq == nil {
		return nil, false
	}
	return v.rowERABToBeModifiedListBearerModReq, true
}

// AsSecondaryRATDataUsageRequest returns the selected SecondaryRATDataUsageRequest value of ERABModifyRequestIEValue and reports whether that alternative is active.
func (v *ERABModifyRequestIEValue) AsSecondaryRATDataUsageRequest() (*s00.SecondaryRATDataUsageRequest, bool) {
	if v == nil || v.id != s00.ProtocolIEID(268) || v.rowSecondaryRATDataUsageRequest == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageRequest, true
}
func (v ERABModifyRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModifyRequestIEValue, error) {
	out := ERABModifyRequestIEValue{id: id}
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
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAggregateMaximumBitrate
		child := scope
		if err := s35.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s35.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s35.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(30):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABToBeModifiedListBearerModReqFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeModifiedListBearerModReq:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeModifiedListBearerModReq = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(268):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SecondaryRATDataUsageRequest"})
		value := s00.SecondaryRATDataUsageRequest(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageRequest:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSecondaryRATDataUsageRequest = &value
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
func (v ERABModifyRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABModifyRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABModifyRequestIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABModifyRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(30):
		if v.rowERABToBeModifiedListBearerModReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyRequestIEs.id-E-RABToBeModifiedListBearerModReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABToBeModifiedListBearerModReqComplete{Value: *v.rowERABToBeModifiedListBearerModReq}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(268):
		if v.rowSecondaryRATDataUsageRequest == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyRequestIEs.id-SecondaryRATDataUsageRequest:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSecondaryRATDataUsageRequest), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModifyRequestIEValue:", v.id)
	}
}

type ERABSetupRequestIEValue struct {
	id                              s00.ProtocolIEID
	received                        aper.WireSpan
	replay                          aper.Snapshot
	opaque                          aper.OpaqueOpenType
	isOpaque                        bool
	rowMMEUES1APID                  *s00.MMEUES1APID
	rowENBUES1APID                  *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate    *s35.UEAggregateMaximumBitrate
	rowERABToBeSetupListBearerSUReq *s29.ERABToBeSetupListBearerSUReq
}

func (v ERABSetupRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(16):
		return v.rowERABToBeSetupListBearerSUReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABSetupRequestIEValue and reports whether the opaque alternative is selected.
func (v *ERABSetupRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABSetupRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs"}}
}
func (ERABSetupRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(16):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABSetupRequestIEValue and reports whether that alternative is active.
func (v *ERABSetupRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABSetupRequestIEValue and reports whether that alternative is active.
func (v *ERABSetupRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of ERABSetupRequestIEValue and reports whether that alternative is active.
func (v *ERABSetupRequestIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeSetupListBearerSUReq returns the selected ERABToBeSetupListBearerSUReq value of ERABSetupRequestIEValue and reports whether that alternative is active.
func (v *ERABSetupRequestIEValue) AsERABToBeSetupListBearerSUReq() (*s29.ERABToBeSetupListBearerSUReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(16) || v.rowERABToBeSetupListBearerSUReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupListBearerSUReq, true
}
func (v ERABSetupRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABSetupRequestIEValue, error) {
	out := ERABSetupRequestIEValue{id: id}
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
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAggregateMaximumBitrate
		child := scope
		if err := s35.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s35.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s35.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(16):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABToBeSetupListBearerSUReqFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupListBearerSUReq:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSetupListBearerSUReq = &value
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
func (v ERABSetupRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABSetupRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABSetupRequestIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABSetupRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(16):
		if v.rowERABToBeSetupListBearerSUReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupRequestIEs.id-E-RABToBeSetupListBearerSUReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABToBeSetupListBearerSUReqComplete{Value: *v.rowERABToBeSetupListBearerSUReq}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABSetupRequestIEValue:", v.id)
	}
}

type HandoverCommandIEValue struct {
	id                                             s00.ProtocolIEID
	received                                       aper.WireSpan
	replay                                         aper.Snapshot
	opaque                                         aper.OpaqueOpenType
	isOpaque                                       bool
	rowMMEUES1APID                                 *s00.MMEUES1APID
	rowENBUES1APID                                 *s00.ENBUES1APID
	rowHandoverType                                *s00.HandoverType
	rowNASSecurityParametersfromEUTRAN             *s00.NASSecurityParametersfromEUTRAN
	rowERABSubjecttoDataForwardingList             *s16.ERABSubjecttoDataForwardingList
	rowERABtoReleaseListHOCmd                      *s16.ERABList
	rowTargetToSourceTransparentContainer          *s00.TargetToSourceTransparentContainer
	rowTargetToSourceTransparentContainerSecondary *s00.TargetToSourceTransparentContainer
	rowCriticalityDiagnostics                      *s22.CriticalityDiagnostics
}

func (v HandoverCommandIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(1):
		return v.rowHandoverType != nil
	case s00.ProtocolIEID(135):
		return v.rowNASSecurityParametersfromEUTRAN != nil
	case s00.ProtocolIEID(12):
		return v.rowERABSubjecttoDataForwardingList != nil
	case s00.ProtocolIEID(13):
		return v.rowERABtoReleaseListHOCmd != nil
	case s00.ProtocolIEID(123):
		return v.rowTargetToSourceTransparentContainer != nil
	case s00.ProtocolIEID(139):
		return v.rowTargetToSourceTransparentContainerSecondary != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverCommandIEValue and reports whether the opaque alternative is selected.
func (v *HandoverCommandIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverCommandIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs"}}
}
func (HandoverCommandIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(135):
		return aper.UnknownSelector
	case s00.ProtocolIEID(12):
		return aper.UnknownSelector
	case s00.ProtocolIEID(13):
		return aper.UnknownSelector
	case s00.ProtocolIEID(123):
		return aper.UnknownSelector
	case s00.ProtocolIEID(139):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
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
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsHandoverType returns the selected HandoverType value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsHandoverType() (*s00.HandoverType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowHandoverType == nil {
		return nil, false
	}
	return v.rowHandoverType, true
}

// AsNASSecurityParametersfromEUTRAN returns the selected NASSecurityParametersfromEUTRAN value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsNASSecurityParametersfromEUTRAN() (*s00.NASSecurityParametersfromEUTRAN, bool) {
	if v == nil || v.id != s00.ProtocolIEID(135) || v.rowNASSecurityParametersfromEUTRAN == nil {
		return nil, false
	}
	return v.rowNASSecurityParametersfromEUTRAN, true
}

// AsERABSubjecttoDataForwardingList returns the selected ERABSubjecttoDataForwardingList value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsERABSubjecttoDataForwardingList() (*s16.ERABSubjecttoDataForwardingList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(12) || v.rowERABSubjecttoDataForwardingList == nil {
		return nil, false
	}
	return v.rowERABSubjecttoDataForwardingList, true
}

// AsERABtoReleaseListHOCmd returns the selected ERABtoReleaseListHOCmd value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsERABtoReleaseListHOCmd() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(13) || v.rowERABtoReleaseListHOCmd == nil {
		return nil, false
	}
	return v.rowERABtoReleaseListHOCmd, true
}

// AsTargetToSourceTransparentContainer returns the selected TargetToSourceTransparentContainer value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsTargetToSourceTransparentContainer() (*s00.TargetToSourceTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(123) || v.rowTargetToSourceTransparentContainer == nil {
		return nil, false
	}
	return v.rowTargetToSourceTransparentContainer, true
}

// AsTargetToSourceTransparentContainerSecondary returns the selected TargetToSourceTransparentContainerSecondary value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsTargetToSourceTransparentContainerSecondary() (*s00.TargetToSourceTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(139) || v.rowTargetToSourceTransparentContainerSecondary == nil {
		return nil, false
	}
	return v.rowTargetToSourceTransparentContainerSecondary, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of HandoverCommandIEValue and reports whether that alternative is active.
func (v *HandoverCommandIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v HandoverCommandIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverCommandIEValue, error) {
	out := HandoverCommandIEValue{id: id}
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
	case s00.ProtocolIEID(1):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 2, Path: "HandoverType"})
		value := s00.HandoverType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "HandoverType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowHandoverType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(135):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NASSecurityParametersfromEUTRAN, error) {
			var v struct {
				Value s00.NASSecurityParametersfromEUTRAN
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.NASSecurityParametersfromEUTRAN(val_value)
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
		out.rowNASSecurityParametersfromEUTRAN = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(12):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABSubjecttoDataForwardingListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABSubjecttoDataForwardingList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABSubjecttoDataForwardingList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(13):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABtoReleaseListHOCmd:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABtoReleaseListHOCmd = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(123):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TargetToSourceTransparentContainer, error) {
			var v struct {
				Value s00.TargetToSourceTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TargetToSourceTransparentContainer(val_value)
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
		out.rowTargetToSourceTransparentContainer = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(139):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TargetToSourceTransparentContainer, error) {
			var v struct {
				Value s00.TargetToSourceTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TargetToSourceTransparentContainer(val_value)
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
		out.rowTargetToSourceTransparentContainerSecondary = &value
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
func (v HandoverCommandIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverCommandIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(1):
		if v.rowHandoverType == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-HandoverType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowHandoverType), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(135):
		if v.rowNASSecurityParametersfromEUTRAN == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-NASSecurityParametersfromE-UTRAN:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NASSecurityParametersfromEUTRAN, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.NASSecurityParametersfromEUTRAN
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
		})(*v.rowNASSecurityParametersfromEUTRAN, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(12):
		if v.rowERABSubjecttoDataForwardingList == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-E-RABSubjecttoDataForwardingList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABSubjecttoDataForwardingListComplete{Value: *v.rowERABSubjecttoDataForwardingList}
		candidate, err := s39.BridgeERABSubjecttoDataForwardingListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(13):
		if v.rowERABtoReleaseListHOCmd == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-E-RABtoReleaseListHOCmd:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABtoReleaseListHOCmd}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(123):
		if v.rowTargetToSourceTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-Target-ToSource-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TargetToSourceTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TargetToSourceTransparentContainer
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
		})(*v.rowTargetToSourceTransparentContainer, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(139):
		if v.rowTargetToSourceTransparentContainerSecondary == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-Target-ToSource-TransparentContainer-Secondary:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TargetToSourceTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TargetToSourceTransparentContainer
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
		})(*v.rowTargetToSourceTransparentContainerSecondary, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverCommandIEs.id-CriticalityDiagnostics:")
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
		return nil, fmt.Errorf("%s id %d has no value", "HandoverCommandIEValue:", v.id)
	}
}

type PathSwitchRequestIEValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowENBUES1APID              *s00.ENBUES1APID
	rowERABToBeSwitchedDLList   *s30.ERABToBeSwitchedDLList
	rowSourceMMEUES1APID        *s00.MMEUES1APID
	rowEUTRANCGI                *s17.EUTRANCGI
	rowTAI                      *s31.TAI
	rowUESecurityCapabilities   *s37.UESecurityCapabilities
	rowCSGId                    *s00.CSGId
	rowCellAccessMode           *s00.CellAccessMode
	rowSourceMMEGUMMEI          *s18.GUMMEI
	rowCSGMembershipStatus      *s00.CSGMembershipStatus
	rowTunnelInformationForBBF  *s34.TunnelInformation
	rowLHNID                    *s00.LHNID
	rowRRCResumeCause           *s00.RRCEstablishmentCause
	rowNRUESecurityCapabilities *s19.NRUESecurityCapabilities
	rowPSCellInformation        *s20.PSCellInformation
	rowLTENTNTAIInformation     *s18.LTENTNTAIInformation
}

func (v PathSwitchRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(22):
		return v.rowERABToBeSwitchedDLList != nil
	case s00.ProtocolIEID(88):
		return v.rowSourceMMEUES1APID != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(145):
		return v.rowCellAccessMode != nil
	case s00.ProtocolIEID(157):
		return v.rowSourceMMEGUMMEI != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(176):
		return v.rowTunnelInformationForBBF != nil
	case s00.ProtocolIEID(186):
		return v.rowLHNID != nil
	case s00.ProtocolIEID(245):
		return v.rowRRCResumeCause != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PathSwitchRequestIEValue and reports whether the opaque alternative is selected.
func (v *PathSwitchRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PathSwitchRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs"}}
}
func (PathSwitchRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(22):
		return aper.UnknownSelector
	case s00.ProtocolIEID(88):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(145):
		return aper.UnknownSelector
	case s00.ProtocolIEID(157):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(176):
		return aper.UnknownSelector
	case s00.ProtocolIEID(186):
		return aper.UnknownSelector
	case s00.ProtocolIEID(245):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(288):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
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

// AsENBUES1APID returns the selected ENBUES1APID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABToBeSwitchedDLList returns the selected ERABToBeSwitchedDLList value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsERABToBeSwitchedDLList() (*s30.ERABToBeSwitchedDLList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(22) || v.rowERABToBeSwitchedDLList == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedDLList, true
}

// AsSourceMMEUES1APID returns the selected SourceMMEUES1APID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsSourceMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(88) || v.rowSourceMMEUES1APID == nil {
		return nil, false
	}
	return v.rowSourceMMEUES1APID, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsTAI() (*s31.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsCSGId returns the selected CSGId value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}

// AsCellAccessMode returns the selected CellAccessMode value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}

// AsSourceMMEGUMMEI returns the selected SourceMMEGUMMEI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsSourceMMEGUMMEI() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(157) || v.rowSourceMMEGUMMEI == nil {
		return nil, false
	}
	return v.rowSourceMMEGUMMEI, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsTunnelInformationForBBF returns the selected TunnelInformationForBBF value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsTunnelInformationForBBF() (*s34.TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}

// AsLHNID returns the selected LHNID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}

// AsRRCResumeCause returns the selected RRCResumeCause value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsRRCResumeCause() (*s00.RRCEstablishmentCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(245) || v.rowRRCResumeCause == nil {
		return nil, false
	}
	return v.rowRRCResumeCause, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsPSCellInformation returns the selected PSCellInformation value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v PathSwitchRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PathSwitchRequestIEValue, error) {
	out := PathSwitchRequestIEValue{id: id}
	switch id {
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
	case s00.ProtocolIEID(22):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABToBeSwitchedDLListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedDLList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSwitchedDLList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(88):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SourceMMEUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSourceMMEUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.EUTRANCGI
		child := scope
		if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		*s17.BridgeEUTRANCGIFieldPerPadding(&value) = padding
		*s17.BridgeEUTRANCGIFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeEUTRANCGIFieldReceivedBytes(&value))
		*s17.BridgeEUTRANCGIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(67):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.TAI
		child := scope
		if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s31.BridgeTAIFieldPerPadding(&value) = padding
		*s31.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeTAIFieldReceivedBytes(&value))
		*s31.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESecurityCapabilities
		child := scope
		if err := s37.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s37.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s37.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(127):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CSGId, error) {
			var v struct{ Value s00.CSGId }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
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
		out.rowCSGId = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(145):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellAccessMode"})
		value := s00.CellAccessMode(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CellAccessMode:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCellAccessMode = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(157):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GUMMEI
		child := scope
		if err := s18.BridgeGUMMEIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceMMEGUMMEI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GUMMEI")
		if err != nil {
			return out, err
		}
		*s18.BridgeGUMMEIFieldPerPadding(&value) = padding
		*s18.BridgeGUMMEIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGUMMEIFieldReceivedBytes(&value))
		*s18.BridgeGUMMEIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSourceMMEGUMMEI = &value
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
	case s00.ProtocolIEID(176):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s34.TunnelInformation
		child := scope
		if err := s34.BridgeTunnelInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		*s34.BridgeTunnelInformationFieldPerPadding(&value) = padding
		*s34.BridgeTunnelInformationFieldReceived(&value) = true
		raw.RetainContents(s34.BridgeTunnelInformationFieldReceivedBytes(&value))
		*s34.BridgeTunnelInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTunnelInformationForBBF = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(186):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.LHNID, error) {
			var v struct{ Value s00.LHNID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 32, 256, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.LHNID(val_value)
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
		out.rowLHNID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(245):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 3, Path: "RRCEstablishmentCause"})
		value := s00.RRCEstablishmentCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RRCResumeCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRRCResumeCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(269):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESecurityCapabilities
		child := scope
		if err := s19.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s19.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s19.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(288):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.PSCellInformation
		child := scope
		if err := s20.BridgePSCellInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PSCellInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PSCellInformation")
		if err != nil {
			return out, err
		}
		*s20.BridgePSCellInformationFieldPerPadding(&value) = padding
		*s20.BridgePSCellInformationFieldReceived(&value) = true
		raw.RetainContents(s20.BridgePSCellInformationFieldReceivedBytes(&value))
		*s20.BridgePSCellInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPSCellInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(339):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.LTENTNTAIInformation
		child := scope
		if err := s18.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s18.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s18.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s18.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowLTENTNTAIInformation = &value
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
func (v PathSwitchRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PathSwitchRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(22):
		if v.rowERABToBeSwitchedDLList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-E-RABToBeSwitchedDLList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABToBeSwitchedDLListComplete{Value: *v.rowERABToBeSwitchedDLList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(88):
		if v.rowSourceMMEUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-SourceMME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowSourceMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-EUTRAN-CGI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeEUTRANCGIMethodMarshalAPERBudget(v.rowEUTRANCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(67):
		if v.rowTAI == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CSG-Id:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CSGId, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CSGId }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 27, 27, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCSGId, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(145):
		if v.rowCellAccessMode == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CellAccessMode:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCellAccessMode), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(157):
		if v.rowSourceMMEGUMMEI == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-SourceMME-GUMMEI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGUMMEIMethodMarshalAPERBudget(v.rowSourceMMEGUMMEI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CSGMembershipStatus:")
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
	case s00.ProtocolIEID(176):
		if v.rowTunnelInformationForBBF == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-Tunnel-Information-for-BBF:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s34.BridgeTunnelInformationMethodMarshalAPERBudget(v.rowTunnelInformationForBBF, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(186):
		if v.rowLHNID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-LHN-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.LHNID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.LHNID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 32, 256, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLHNID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(245):
		if v.rowRRCResumeCause == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-RRC-Resume-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRRCResumeCause), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-PSCellInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgePSCellInformationMethodMarshalAPERBudget(v.rowPSCellInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-LTE-NTN-TAI-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PathSwitchRequestIEValue:", v.id)
	}
}

type DownlinkS1cdma2000tunnellingIETable struct{}

func DownlinkS1cdma2000tunnellingIEs() DownlinkS1cdma2000tunnellingIETable {
	return DownlinkS1cdma2000tunnellingIETable{}
}

// ID returns the ASN.1 object-set identity of DownlinkS1cdma2000tunnellingIETable.
func (DownlinkS1cdma2000tunnellingIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DownlinkS1cdma2000tunnellingIETable.
func (DownlinkS1cdma2000tunnellingIETable) Table() s00.DownlinkS1cdma2000tunnellingIEValueIETable {
	return func() s00.DownlinkS1cdma2000tunnellingIEValueIETable {
		sealed := s00.DownlinkS1cdma2000tunnellingIEValueIETable{}
		*s00.BridgeDownlinkS1cdma2000tunnellingIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DownlinkS1cdma2000tunnellingIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) MMEUES1APID() DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding {
	return DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (DownlinkS1cdma2000tunnellingIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) ENBUES1APID() DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding {
	return DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (DownlinkS1cdma2000tunnellingIETable) infoERABSubjecttoDataForwardingList() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(12), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSubjecttoDataForwardingList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-E-RABSubjecttoDataForwardingList"}}}
}

// ERABSubjecttoDataForwardingList returns the typed binding for the ERABSubjecttoDataForwardingList row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) ERABSubjecttoDataForwardingList() DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding {
	return DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding{info: t.infoERABSubjecttoDataForwardingList(), codec: func() s16.ERABSubjecttoDataForwardingListValueCodec {
		sealed := s16.ERABSubjecttoDataForwardingListValueCodec{}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldPath(&sealed) = "ERABSubjecttoDataForwardingList"
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSubjecttoDataForwardingList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(12), raw)
			if err != nil {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, err
			}
			value, ok := decoded.AsERABSubjecttoDataForwardingList()
			if !ok {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-E-RABSubjecttoDataForwardingList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldEncode(&sealed) = func(value s16.ERABSubjecttoDataForwardingList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(12), rowERABSubjecttoDataForwardingList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldCapture(&sealed) = func(v s16.ERABSubjecttoDataForwardingList, options aper.DecodeState) (s16.ERABSubjecttoDataForwardingList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABSubjecttoDataForwardingList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldCompare(&sealed) = func(v s16.ERABSubjecttoDataForwardingList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABSubjecttoDataForwardingList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSubjecttoDataForwardingList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABSubjecttoDataForwardingList) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(12), rowERABSubjecttoDataForwardingList: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s16.ERABSubjecttoDataForwardingList, bool) {
			return value.AsERABSubjecttoDataForwardingList()
		}}
}
func (DownlinkS1cdma2000tunnellingIETable) infoCdma2000HOStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(83), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000HOStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-cdma2000HOStatus"}}}
}

// Cdma2000HOStatus returns the typed binding for the Cdma2000HOStatus row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) Cdma2000HOStatus() DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding {
	return DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding{info: t.infoCdma2000HOStatus(), codec: func() s00.Cdma2000HOStatusValueCodec {
		sealed := s00.Cdma2000HOStatusValueCodec{}
		*s00.BridgeCdma2000HOStatusValueCodecFieldPath(&sealed) = "Cdma2000HOStatus"
		*s00.BridgeCdma2000HOStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000HOStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000HOStatus
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(83), raw)
			if err != nil {
				var empty s00.Cdma2000HOStatus
				return empty, err
			}
			value, ok := decoded.AsCdma2000HOStatus()
			if !ok {
				var empty s00.Cdma2000HOStatus
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-cdma2000HOStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000HOStatusValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000HOStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(83), rowCdma2000HOStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000HOStatusValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000HOStatus, options aper.DecodeState) (s00.Cdma2000HOStatus, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000HOStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000HOStatusValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000HOStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000HOStatus(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000HOStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000HOStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000HOStatus) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(83), rowCdma2000HOStatus: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HOStatus, bool) {
			return value.AsCdma2000HOStatus()
		}}
}
func (DownlinkS1cdma2000tunnellingIETable) infoCdma2000RATType() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(71), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000RATType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-cdma2000RATType"}}}
}

// Cdma2000RATType returns the typed binding for the Cdma2000RATType row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) Cdma2000RATType() DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding {
	return DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding{info: t.infoCdma2000RATType(), codec: func() s00.Cdma2000RATTypeValueCodec {
		sealed := s00.Cdma2000RATTypeValueCodec{}
		*s00.BridgeCdma2000RATTypeValueCodecFieldPath(&sealed) = "Cdma2000RATType"
		*s00.BridgeCdma2000RATTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000RATType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000RATType
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(71), raw)
			if err != nil {
				var empty s00.Cdma2000RATType
				return empty, err
			}
			value, ok := decoded.AsCdma2000RATType()
			if !ok {
				var empty s00.Cdma2000RATType
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-cdma2000RATType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000RATType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(71), rowCdma2000RATType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000RATType, options aper.DecodeState) (s00.Cdma2000RATType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000RATType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000RATType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000RATType(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000RATType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000RATType) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(71), rowCdma2000RATType: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
			return value.AsCdma2000RATType()
		}}
}
func (DownlinkS1cdma2000tunnellingIETable) infoCdma2000PDU() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(70), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkS1cdma2000tunnellingIEs", Row: "id-cdma2000PDU"}}}
}

// Cdma2000PDU returns the typed binding for the Cdma2000PDU row of DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) Cdma2000PDU() DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding {
	return DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding{info: t.infoCdma2000PDU(), codec: func() s00.Cdma2000PDUValueCodec {
		sealed := s00.Cdma2000PDUValueCodec{}
		*s00.BridgeCdma2000PDUValueCodecFieldPath(&sealed) = "Cdma2000PDU"
		*s00.BridgeCdma2000PDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000PDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000PDU
				return empty, err
			}
			var zero DownlinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(70), raw)
			if err != nil {
				var empty s00.Cdma2000PDU
				return empty, err
			}
			value, ok := decoded.AsCdma2000PDU()
			if !ok {
				var empty s00.Cdma2000PDU
				return empty, fmt.Errorf("binding DownlinkS1cdma2000tunnellingIEs.id-cdma2000PDU: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000PDUValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000PDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(70), rowCdma2000PDU: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000PDUValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000PDU, options aper.DecodeState) (s00.Cdma2000PDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000PDU(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000PDUValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000PDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000PDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s00.BridgeCdma2000PDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000PDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000PDU) DownlinkS1cdma2000tunnellingIEValue {
			return DownlinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(70), rowCdma2000PDU: &value}
		}, get: func(value *DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) {
			return value.AsCdma2000PDU()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DownlinkS1cdma2000tunnellingIETable.
func (t DownlinkS1cdma2000tunnellingIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DownlinkS1cdma2000tunnellingIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(12):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSubjecttoDataForwardingList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(83):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000HOStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(71):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000RATType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(70):
		return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000PDU requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DownlinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		return DownlinkS1cdma2000tunnellingIEField{Id: id, Criticality: criticality, Value: DownlinkS1cdma2000tunnellingIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyRequestIETable struct{}

func ERABModifyRequestIEs() ERABModifyRequestIETable { return ERABModifyRequestIETable{} }

// ID returns the ASN.1 object-set identity of ERABModifyRequestIETable.
func (ERABModifyRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModifyRequestIETable.
func (ERABModifyRequestIETable) Table() s00.ERABModifyRequestIEValueIETable {
	return func() s00.ERABModifyRequestIEValueIETable {
		sealed := s00.ERABModifyRequestIEValueIETable{}
		*s00.BridgeERABModifyRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModifyRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) MMEUES1APID() ERABModifyRequestMMEUES1APIDIEBinding {
	return ERABModifyRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero ERABModifyRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABModifyRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABModifyRequestIEValue {
			return ERABModifyRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABModifyRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABModifyRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) ENBUES1APID() ERABModifyRequestENBUES1APIDIEBinding {
	return ERABModifyRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero ERABModifyRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABModifyRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABModifyRequestIEValue {
			return ERABModifyRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABModifyRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABModifyRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) UEaggregateMaximumBitrate() ERABModifyRequestUEAggregateMaximumBitrateIEBinding {
	return ERABModifyRequestUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s35.UEAggregateMaximumBitrateValueCodec {
		sealed := s35.UEAggregateMaximumBitrateValueCodec{}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			var zero ERABModifyRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s35.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding E-RABModifyRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s35.UEAggregateMaximumBitrate, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s35.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAggregateMaximumBitrate) ERABModifyRequestIEValue {
			return ERABModifyRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *ERABModifyRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (ERABModifyRequestIETable) infoERABToBeModifiedListBearerModReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyRequestIEs().ID(), ID: s00.ProtocolIEID(30), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedListBearerModReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs", Row: "id-E-RABToBeModifiedListBearerModReq"}}}
}

// ERABToBeModifiedListBearerModReq returns the typed binding for the ERABToBeModifiedListBearerModReq row of ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) ERABToBeModifiedListBearerModReq() ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding {
	return ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding{info: t.infoERABToBeModifiedListBearerModReq(), codec: func() s25.ERABToBeModifiedListBearerModReqValueCodec {
		sealed := s25.ERABToBeModifiedListBearerModReqValueCodec{}
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldPath(&sealed) = "ERABToBeModifiedListBearerModReq"
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ERABToBeModifiedListBearerModReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s25.ERABToBeModifiedListBearerModReq
				return empty, err
			}
			var zero ERABModifyRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(30), raw)
			if err != nil {
				var empty s25.ERABToBeModifiedListBearerModReq
				return empty, err
			}
			value, ok := decoded.AsERABToBeModifiedListBearerModReq()
			if !ok {
				var empty s25.ERABToBeModifiedListBearerModReq
				return empty, fmt.Errorf("binding E-RABModifyRequestIEs.id-E-RABToBeModifiedListBearerModReq: no selected value")
			}
			return *value, nil
		}
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldEncode(&sealed) = func(value s25.ERABToBeModifiedListBearerModReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyRequestIEValue{id: s00.ProtocolIEID(30), rowERABToBeModifiedListBearerModReq: &value}).encodeFresh(fresh, budget)
		}
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldCapture(&sealed) = func(v s25.ERABToBeModifiedListBearerModReq, options aper.DecodeState) (s25.ERABToBeModifiedListBearerModReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APERABToBeModifiedListBearerModReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldCompare(&sealed) = func(v s25.ERABToBeModifiedListBearerModReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APERABToBeModifiedListBearerModReq(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeERABToBeModifiedListBearerModReqValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeModifiedListBearerModReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s25.ERABToBeModifiedListBearerModReq) ERABModifyRequestIEValue {
			return ERABModifyRequestIEValue{id: s00.ProtocolIEID(30), rowERABToBeModifiedListBearerModReq: &value}
		}, get: func(value *ERABModifyRequestIEValue) (*s25.ERABToBeModifiedListBearerModReq, bool) {
			return value.AsERABToBeModifiedListBearerModReq()
		}}
}
func (ERABModifyRequestIETable) infoSecondaryRATDataUsageRequest() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyRequestIEs().ID(), ID: s00.ProtocolIEID(268), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageRequest"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyRequestIEs", Row: "id-SecondaryRATDataUsageRequest"}}}
}

// SecondaryRATDataUsageRequest returns the typed binding for the SecondaryRATDataUsageRequest row of ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) SecondaryRATDataUsageRequest() ERABModifyRequestSecondaryRATDataUsageRequestIEBinding {
	return ERABModifyRequestSecondaryRATDataUsageRequestIEBinding{info: t.infoSecondaryRATDataUsageRequest(), codec: func() s01.SecondaryRATDataUsageRequestValueCodec {
		sealed := s01.SecondaryRATDataUsageRequestValueCodec{}
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageRequest"
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecondaryRATDataUsageRequest, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SecondaryRATDataUsageRequest
				return empty, err
			}
			var zero ERABModifyRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(268), raw)
			if err != nil {
				var empty s00.SecondaryRATDataUsageRequest
				return empty, err
			}
			value, ok := decoded.AsSecondaryRATDataUsageRequest()
			if !ok {
				var empty s00.SecondaryRATDataUsageRequest
				return empty, fmt.Errorf("binding E-RABModifyRequestIEs.id-SecondaryRATDataUsageRequest: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldEncode(&sealed) = func(value s00.SecondaryRATDataUsageRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyRequestIEValue{id: s00.ProtocolIEID(268), rowSecondaryRATDataUsageRequest: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldCapture(&sealed) = func(v s00.SecondaryRATDataUsageRequest, options aper.DecodeState) (s00.SecondaryRATDataUsageRequest, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSecondaryRATDataUsageRequest(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldCompare(&sealed) = func(v s00.SecondaryRATDataUsageRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s06.BridgeCompareS1APSecondaryRATDataUsageRequest(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSecondaryRATDataUsageRequestValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageRequest"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SecondaryRATDataUsageRequest) ERABModifyRequestIEValue {
			return ERABModifyRequestIEValue{id: s00.ProtocolIEID(268), rowSecondaryRATDataUsageRequest: &value}
		}, get: func(value *ERABModifyRequestIEValue) (*s00.SecondaryRATDataUsageRequest, bool) {
			return value.AsSecondaryRATDataUsageRequest()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModifyRequestIETable.
func (t ERABModifyRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABModifyRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(30):
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeModifiedListBearerModReq requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(268):
		return ERABModifyRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageRequest requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyRequestIEField{Id: id, Criticality: criticality, Value: ERABModifyRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupRequestIETable struct{}

func ERABSetupRequestIEs() ERABSetupRequestIETable { return ERABSetupRequestIETable{} }

// ID returns the ASN.1 object-set identity of ERABSetupRequestIETable.
func (ERABSetupRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupRequestIETable.
func (ERABSetupRequestIETable) Table() s00.ERABSetupRequestIEValueIETable {
	return func() s00.ERABSetupRequestIEValueIETable {
		sealed := s00.ERABSetupRequestIEValueIETable{}
		*s00.BridgeERABSetupRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSetupRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABSetupRequestIETable.
func (t ERABSetupRequestIETable) MMEUES1APID() ERABSetupRequestMMEUES1APIDIEBinding {
	return ERABSetupRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero ERABSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABSetupRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABSetupRequestIEValue {
			return ERABSetupRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABSetupRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABSetupRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABSetupRequestIETable.
func (t ERABSetupRequestIETable) ENBUES1APID() ERABSetupRequestENBUES1APIDIEBinding {
	return ERABSetupRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero ERABSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABSetupRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABSetupRequestIEValue {
			return ERABSetupRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABSetupRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABSetupRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of ERABSetupRequestIETable.
func (t ERABSetupRequestIETable) UEaggregateMaximumBitrate() ERABSetupRequestUEAggregateMaximumBitrateIEBinding {
	return ERABSetupRequestUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s35.UEAggregateMaximumBitrateValueCodec {
		sealed := s35.UEAggregateMaximumBitrateValueCodec{}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			var zero ERABSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s35.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding E-RABSetupRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s35.UEAggregateMaximumBitrate, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s35.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAggregateMaximumBitrate) ERABSetupRequestIEValue {
			return ERABSetupRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *ERABSetupRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (ERABSetupRequestIETable) infoERABToBeSetupListBearerSUReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupRequestIEs().ID(), ID: s00.ProtocolIEID(16), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupListBearerSUReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupRequestIEs", Row: "id-E-RABToBeSetupListBearerSUReq"}}}
}

// ERABToBeSetupListBearerSUReq returns the typed binding for the ERABToBeSetupListBearerSUReq row of ERABSetupRequestIETable.
func (t ERABSetupRequestIETable) ERABToBeSetupListBearerSUReq() ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding {
	return ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding{info: t.infoERABToBeSetupListBearerSUReq(), codec: func() s29.ERABToBeSetupListBearerSUReqValueCodec {
		sealed := s29.ERABToBeSetupListBearerSUReqValueCodec{}
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldPath(&sealed) = "ERABToBeSetupListBearerSUReq"
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeSetupListBearerSUReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s29.ERABToBeSetupListBearerSUReq
				return empty, err
			}
			var zero ERABSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(16), raw)
			if err != nil {
				var empty s29.ERABToBeSetupListBearerSUReq
				return empty, err
			}
			value, ok := decoded.AsERABToBeSetupListBearerSUReq()
			if !ok {
				var empty s29.ERABToBeSetupListBearerSUReq
				return empty, fmt.Errorf("binding E-RABSetupRequestIEs.id-E-RABToBeSetupListBearerSUReq: no selected value")
			}
			return *value, nil
		}
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeSetupListBearerSUReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupRequestIEValue{id: s00.ProtocolIEID(16), rowERABToBeSetupListBearerSUReq: &value}).encodeFresh(fresh, budget)
		}
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeSetupListBearerSUReq, options aper.DecodeState) (s29.ERABToBeSetupListBearerSUReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APERABToBeSetupListBearerSUReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeSetupListBearerSUReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s29.BridgeCompareS1APERABToBeSetupListBearerSUReq(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeSetupListBearerSUReqValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSetupListBearerSUReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s29.ERABToBeSetupListBearerSUReq) ERABSetupRequestIEValue {
			return ERABSetupRequestIEValue{id: s00.ProtocolIEID(16), rowERABToBeSetupListBearerSUReq: &value}
		}, get: func(value *ERABSetupRequestIEValue) (*s29.ERABToBeSetupListBearerSUReq, bool) {
			return value.AsERABToBeSetupListBearerSUReq()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupRequestIETable.
func (t ERABSetupRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABSetupRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(16):
		return ERABSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSetupListBearerSUReq requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupRequestIEField{Id: id, Criticality: criticality, Value: ERABSetupRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverCommandIETable struct{}

func HandoverCommandIEs() HandoverCommandIETable { return HandoverCommandIETable{} }

// ID returns the ASN.1 object-set identity of HandoverCommandIETable.
func (HandoverCommandIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverCommandIETable.
func (HandoverCommandIETable) Table() s00.HandoverCommandIEValueIETable {
	return func() s00.HandoverCommandIEValueIETable {
		sealed := s00.HandoverCommandIEValueIETable{}
		*s00.BridgeHandoverCommandIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverCommandIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverCommandIETable.
func (t HandoverCommandIETable) MMEUES1APID() HandoverCommandMMEUES1APIDIEBinding {
	return HandoverCommandMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverCommandIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverCommandIETable.
func (t HandoverCommandIETable) ENBUES1APID() HandoverCommandENBUES1APIDIEBinding {
	return HandoverCommandENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverCommandIETable) infoHandoverType() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-HandoverType"}}}
}

// HandoverType returns the typed binding for the HandoverType row of HandoverCommandIETable.
func (t HandoverCommandIETable) HandoverType() HandoverCommandHandoverTypeIEBinding {
	return HandoverCommandHandoverTypeIEBinding{info: t.infoHandoverType(), codec: func() s00.HandoverTypeValueCodec {
		sealed := s00.HandoverTypeValueCodec{}
		*s00.BridgeHandoverTypeValueCodecFieldPath(&sealed) = "HandoverType"
		*s00.BridgeHandoverTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.HandoverType
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s00.HandoverType
				return empty, err
			}
			value, ok := decoded.AsHandoverType()
			if !ok {
				var empty s00.HandoverType
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-HandoverType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeHandoverTypeValueCodecFieldEncode(&sealed) = func(value s00.HandoverType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(1), rowHandoverType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeHandoverTypeValueCodecFieldCapture(&sealed) = func(v s00.HandoverType, options aper.DecodeState) (s00.HandoverType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHandoverType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHandoverTypeValueCodecFieldCompare(&sealed) = func(v s00.HandoverType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHandoverType(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeHandoverTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.HandoverType) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(1), rowHandoverType: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.HandoverType, bool) { return value.AsHandoverType() }}
}
func (HandoverCommandIETable) infoNASSecurityParametersfromEUTRAN() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(135), Criticality: s00.CriticalityReject, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NASSecurityParametersfromE-UTRAN"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-NASSecurityParametersfromE-UTRAN"}}}
}

// NASSecurityParametersfromEUTRAN returns the typed binding for the NASSecurityParametersfromEUTRAN row of HandoverCommandIETable.
func (t HandoverCommandIETable) NASSecurityParametersfromEUTRAN() HandoverCommandNASSecurityParametersfromEUTRANIEBinding {
	return HandoverCommandNASSecurityParametersfromEUTRANIEBinding{info: t.infoNASSecurityParametersfromEUTRAN(), codec: func() s01.NASSecurityParametersfromEUTRANValueCodec {
		sealed := s01.NASSecurityParametersfromEUTRANValueCodec{}
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldPath(&sealed) = "NASSecurityParametersfromEUTRAN"
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASSecurityParametersfromEUTRAN, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASSecurityParametersfromEUTRAN
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(135), raw)
			if err != nil {
				var empty s00.NASSecurityParametersfromEUTRAN
				return empty, err
			}
			value, ok := decoded.AsNASSecurityParametersfromEUTRAN()
			if !ok {
				var empty s00.NASSecurityParametersfromEUTRAN
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-NASSecurityParametersfromE-UTRAN: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldEncode(&sealed) = func(value s00.NASSecurityParametersfromEUTRAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(135), rowNASSecurityParametersfromEUTRAN: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldCapture(&sealed) = func(v s00.NASSecurityParametersfromEUTRAN, options aper.DecodeState) (s00.NASSecurityParametersfromEUTRAN, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNASSecurityParametersfromEUTRAN(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldCompare(&sealed) = func(v s00.NASSecurityParametersfromEUTRAN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNASSecurityParametersfromEUTRAN(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNASSecurityParametersfromEUTRANValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASSecurityParametersfromEUTRAN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NASSecurityParametersfromEUTRAN) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(135), rowNASSecurityParametersfromEUTRAN: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.NASSecurityParametersfromEUTRAN, bool) {
			return value.AsNASSecurityParametersfromEUTRAN()
		}}
}
func (HandoverCommandIETable) infoERABSubjecttoDataForwardingList() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(12), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSubjecttoDataForwardingList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-E-RABSubjecttoDataForwardingList"}}}
}

// ERABSubjecttoDataForwardingList returns the typed binding for the ERABSubjecttoDataForwardingList row of HandoverCommandIETable.
func (t HandoverCommandIETable) ERABSubjecttoDataForwardingList() HandoverCommandERABSubjecttoDataForwardingListIEBinding {
	return HandoverCommandERABSubjecttoDataForwardingListIEBinding{info: t.infoERABSubjecttoDataForwardingList(), codec: func() s16.ERABSubjecttoDataForwardingListValueCodec {
		sealed := s16.ERABSubjecttoDataForwardingListValueCodec{}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldPath(&sealed) = "ERABSubjecttoDataForwardingList"
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABSubjecttoDataForwardingList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(12), raw)
			if err != nil {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, err
			}
			value, ok := decoded.AsERABSubjecttoDataForwardingList()
			if !ok {
				var empty s16.ERABSubjecttoDataForwardingList
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-E-RABSubjecttoDataForwardingList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldEncode(&sealed) = func(value s16.ERABSubjecttoDataForwardingList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(12), rowERABSubjecttoDataForwardingList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldCapture(&sealed) = func(v s16.ERABSubjecttoDataForwardingList, options aper.DecodeState) (s16.ERABSubjecttoDataForwardingList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABSubjecttoDataForwardingList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldCompare(&sealed) = func(v s16.ERABSubjecttoDataForwardingList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABSubjecttoDataForwardingList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABSubjecttoDataForwardingListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSubjecttoDataForwardingList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABSubjecttoDataForwardingList) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(12), rowERABSubjecttoDataForwardingList: &value}
		}, get: func(value *HandoverCommandIEValue) (*s16.ERABSubjecttoDataForwardingList, bool) {
			return value.AsERABSubjecttoDataForwardingList()
		}}
}
func (HandoverCommandIETable) infoERABtoReleaseListHOCmd() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(13), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-E-RABtoReleaseListHOCmd"}}}
}

// ERABtoReleaseListHOCmd returns the typed binding for the ERABtoReleaseListHOCmd row of HandoverCommandIETable.
func (t HandoverCommandIETable) ERABtoReleaseListHOCmd() HandoverCommandERABListIEBinding {
	return HandoverCommandERABListIEBinding{info: t.infoERABtoReleaseListHOCmd(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(13), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			value, ok := decoded.AsERABtoReleaseListHOCmd()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-E-RABtoReleaseListHOCmd: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(13), rowERABtoReleaseListHOCmd: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s16.ERABList) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(13), rowERABtoReleaseListHOCmd: &value}
		}, get: func(value *HandoverCommandIEValue) (*s16.ERABList, bool) { return value.AsERABtoReleaseListHOCmd() }}
}
func (HandoverCommandIETable) infoTargetToSourceTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(123), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Target-ToSource-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-Target-ToSource-TransparentContainer"}}}
}

// TargetToSourceTransparentContainer returns the typed binding for the TargetToSourceTransparentContainer row of HandoverCommandIETable.
func (t HandoverCommandIETable) TargetToSourceTransparentContainer() HandoverCommandTargetToSourceTransparentContainerIEBinding {
	return HandoverCommandTargetToSourceTransparentContainerIEBinding{info: t.infoTargetToSourceTransparentContainer(), codec: func() s01.TargetToSourceTransparentContainerValueCodec {
		sealed := s01.TargetToSourceTransparentContainerValueCodec{}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldPath(&sealed) = "TargetToSourceTransparentContainer"
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(123), raw)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, err
			}
			value, ok := decoded.AsTargetToSourceTransparentContainer()
			if !ok {
				var empty s00.TargetToSourceTransparentContainer
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-Target-ToSource-TransparentContainer: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetToSourceTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(123), rowTargetToSourceTransparentContainer: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetToSourceTransparentContainer, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetToSourceTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetToSourceTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTargetToSourceTransparentContainer(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetToSourceTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TargetToSourceTransparentContainer) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(123), rowTargetToSourceTransparentContainer: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.TargetToSourceTransparentContainer, bool) {
			return value.AsTargetToSourceTransparentContainer()
		}}
}
func (HandoverCommandIETable) infoTargetToSourceTransparentContainerSecondary() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(139), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Target-ToSource-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-Target-ToSource-TransparentContainer-Secondary"}}}
}

// TargetToSourceTransparentContainerSecondary returns the typed binding for the TargetToSourceTransparentContainerSecondary row of HandoverCommandIETable.
func (t HandoverCommandIETable) TargetToSourceTransparentContainerSecondary() HandoverCommandTargetToSourceTransparentContainerIEBinding {
	return HandoverCommandTargetToSourceTransparentContainerIEBinding{info: t.infoTargetToSourceTransparentContainerSecondary(), codec: func() s01.TargetToSourceTransparentContainerValueCodec {
		sealed := s01.TargetToSourceTransparentContainerValueCodec{}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldPath(&sealed) = "TargetToSourceTransparentContainer"
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(139), raw)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, err
			}
			value, ok := decoded.AsTargetToSourceTransparentContainerSecondary()
			if !ok {
				var empty s00.TargetToSourceTransparentContainer
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-Target-ToSource-TransparentContainer-Secondary: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetToSourceTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(139), rowTargetToSourceTransparentContainerSecondary: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetToSourceTransparentContainer, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetToSourceTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetToSourceTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTargetToSourceTransparentContainer(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetToSourceTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TargetToSourceTransparentContainer) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(139), rowTargetToSourceTransparentContainerSecondary: &value}
		}, get: func(value *HandoverCommandIEValue) (*s00.TargetToSourceTransparentContainer, bool) {
			return value.AsTargetToSourceTransparentContainerSecondary()
		}}
}
func (HandoverCommandIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCommandIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCommandIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of HandoverCommandIETable.
func (t HandoverCommandIETable) CriticalityDiagnostics() HandoverCommandCriticalityDiagnosticsIEBinding {
	return HandoverCommandCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero HandoverCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding HandoverCommandIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCommandIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) HandoverCommandIEValue {
			return HandoverCommandIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *HandoverCommandIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverCommandIETable.
func (t HandoverCommandIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(135):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-NASSecurityParametersfromE-UTRAN requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(12):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSubjecttoDataForwardingList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(13):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABtoReleaseListHOCmd requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(123):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-Target-ToSource-TransparentContainer requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(139):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-Target-ToSource-TransparentContainer-Secondary requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return HandoverCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverCommandIEField{Id: id, Criticality: criticality, Value: HandoverCommandIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// Cdma2000HOStatusCodec binds the complete APER value type.
func Cdma2000HOStatusCodec() s00.Cdma2000HOStatusValueCodec {
	return DownlinkS1cdma2000tunnellingIEs().Cdma2000HOStatus().Codec()
}

// Cdma2000PDUCodec binds the complete APER value type.
func Cdma2000PDUCodec() s00.Cdma2000PDUValueCodec {
	return DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().Codec()
}

// Cdma2000RATTypeCodec binds the complete APER value type.
func Cdma2000RATTypeCodec() s00.Cdma2000RATTypeValueCodec {
	return DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().Codec()
}

// ERABSubjecttoDataForwardingListCodec binds the complete APER value type.
func ERABSubjecttoDataForwardingListCodec() s16.ERABSubjecttoDataForwardingListValueCodec {
	return DownlinkS1cdma2000tunnellingIEs().ERABSubjecttoDataForwardingList().Codec()
}

// ERABToBeModifiedListBearerModReqCodec binds the complete APER value type.
func ERABToBeModifiedListBearerModReqCodec() s25.ERABToBeModifiedListBearerModReqValueCodec {
	return ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Codec()
}

// ERABToBeSetupListBearerSUReqCodec binds the complete APER value type.
func ERABToBeSetupListBearerSUReqCodec() s29.ERABToBeSetupListBearerSUReqValueCodec {
	return ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Codec()
}

// HandoverTypeCodec binds the complete APER value type.
func HandoverTypeCodec() s00.HandoverTypeValueCodec {
	return HandoverCommandIEs().HandoverType().Codec()
}

// NASSecurityParametersfromEUTRANCodec binds the complete APER value type.
func NASSecurityParametersfromEUTRANCodec() s01.NASSecurityParametersfromEUTRANValueCodec {
	return HandoverCommandIEs().NASSecurityParametersfromEUTRAN().Codec()
}

// SecondaryRATDataUsageRequestCodec binds the complete APER value type.
func SecondaryRATDataUsageRequestCodec() s01.SecondaryRATDataUsageRequestValueCodec {
	return ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Codec()
}

// TargetToSourceTransparentContainerCodec binds the complete APER value type.
func TargetToSourceTransparentContainerCodec() s01.TargetToSourceTransparentContainerValueCodec {
	return HandoverCommandIEs().TargetToSourceTransparentContainer().Codec()
}

// UEAggregateMaximumBitrateCodec binds the complete APER value type.
func UEAggregateMaximumBitrateCodec() s35.UEAggregateMaximumBitrateValueCodec {
	return ERABModifyRequestIEs().UEaggregateMaximumBitrate().Codec()
}
func BridgeDownlinkS1cdma2000tunnellingAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000HOStatusIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) *s00.Cdma2000HOStatusValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000HOStatusIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HOStatus, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000HOStatusIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000HOStatusIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingCdma2000HOStatusIEBinding) *func(s00.Cdma2000HOStatus) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.Cdma2000PDUValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(s00.Cdma2000PDU) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.Cdma2000RATTypeValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(s00.Cdma2000RATType) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(s00.ENBUES1APID) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) *s16.ERABSubjecttoDataForwardingListValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s16.ERABSubjecttoDataForwardingList, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingERABSubjecttoDataForwardingListIEBinding) *func(s16.ERABSubjecttoDataForwardingList) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingFieldExtCount(v *DownlinkS1cdma2000tunnelling) *int64 {
	return &v.extCount
}
func BridgeDownlinkS1cdma2000tunnellingFieldExtData(v *DownlinkS1cdma2000tunnelling) *[][]byte {
	return &v.extData
}
func BridgeDownlinkS1cdma2000tunnellingFieldExtOrigin(v *DownlinkS1cdma2000tunnelling) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDownlinkS1cdma2000tunnellingFieldExtPresent(v *DownlinkS1cdma2000tunnelling) *[]bool {
	return &v.extPresent
}
func BridgeDownlinkS1cdma2000tunnellingFieldExtWire(v *DownlinkS1cdma2000tunnelling) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDownlinkS1cdma2000tunnellingFieldPerExtPadding(v *DownlinkS1cdma2000tunnelling) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDownlinkS1cdma2000tunnellingFieldPerPadding(v *DownlinkS1cdma2000tunnelling) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDownlinkS1cdma2000tunnellingFieldProtocolIEsIndef(v *DownlinkS1cdma2000tunnelling) *bool {
	return &v.protocolIEsIndef
}
func BridgeDownlinkS1cdma2000tunnellingFieldReceived(v *DownlinkS1cdma2000tunnelling) *bool {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingFieldReceivedAbsolute(v *DownlinkS1cdma2000tunnelling) *bool {
	return &v.receivedAbsolute
}
func BridgeDownlinkS1cdma2000tunnellingFieldReceivedBytes(v *DownlinkS1cdma2000tunnelling) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDownlinkS1cdma2000tunnellingFieldReceivedLocation(v *DownlinkS1cdma2000tunnelling) *aper.Location {
	return &v.receivedLocation
}
func BridgeDownlinkS1cdma2000tunnellingFieldReplay(v *DownlinkS1cdma2000tunnelling) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingFieldStream(v *DownlinkS1cdma2000tunnelling) *aper.WireSpan {
	return &v.stream
}
func BridgeDownlinkS1cdma2000tunnellingFieldWithoutReplay(v *DownlinkS1cdma2000tunnelling) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *func(DownlinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *func(DownlinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEContainer, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *func(DownlinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingIEContainerValueCodec, a0 DownlinkS1cdma2000tunnellingIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingIEContainerValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingIEContainerValueCodec, a0 DownlinkS1cdma2000tunnellingIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldFieldReceived(v *DownlinkS1cdma2000tunnellingIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldFieldReplay(v *DownlinkS1cdma2000tunnellingIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldFieldStream(v *DownlinkS1cdma2000tunnellingIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEField) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(v *DownlinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(v *DownlinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *func(DownlinkS1cdma2000tunnellingIEField, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *func(DownlinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEField, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *func(DownlinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingIEFieldValueCodec, a0 DownlinkS1cdma2000tunnellingIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingIEFieldValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingIEFieldValueCodec, a0 DownlinkS1cdma2000tunnellingIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoCdma2000HOStatus(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000HOStatus()
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoCdma2000PDU(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000PDU()
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoCdma2000RATType(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000RATType()
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoENBUES1APID(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoERABSubjecttoDataForwardingList(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoERABSubjecttoDataForwardingList()
}
func BridgeDownlinkS1cdma2000tunnellingIETableMethodInfoMMEUES1APID(v DownlinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(v *DownlinkS1cdma2000tunnellingIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldIsOpaque(v *DownlinkS1cdma2000tunnellingIEValue) *bool {
	return &v.isOpaque
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldOpaque(v *DownlinkS1cdma2000tunnellingIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000HOStatus(v *DownlinkS1cdma2000tunnellingIEValue) **s00.Cdma2000HOStatus {
	return &v.rowCdma2000HOStatus
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(v *DownlinkS1cdma2000tunnellingIEValue) **s00.Cdma2000PDU {
	return &v.rowCdma2000PDU
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(v *DownlinkS1cdma2000tunnellingIEValue) **s00.Cdma2000RATType {
	return &v.rowCdma2000RATType
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(v *DownlinkS1cdma2000tunnellingIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowERABSubjecttoDataForwardingList(v *DownlinkS1cdma2000tunnellingIEValue) **s16.ERABSubjecttoDataForwardingList {
	return &v.rowERABSubjecttoDataForwardingList
}
func BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(v *DownlinkS1cdma2000tunnellingIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodCaptureSemantics(v DownlinkS1cdma2000tunnellingIEValue, a0 aper.SemanticCapture) DownlinkS1cdma2000tunnellingIEValue {
	return v.captureSemantics(a0)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodCompareSemantics(v DownlinkS1cdma2000tunnellingIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodDecode(v DownlinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (DownlinkS1cdma2000tunnellingIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodEncode(v DownlinkS1cdma2000tunnellingIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodEncodeFresh(v DownlinkS1cdma2000tunnellingIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodMatchesID(v DownlinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodReason(v DownlinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueMethodRule(v DownlinkS1cdma2000tunnellingIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldContext(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldReceived(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldReplay(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec, a0 DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldCodec(v *DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeDownlinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldGet(v *DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(*DownlinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeDownlinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInfo(v *DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInject(v *DownlinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) DownlinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(v *DownlinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudgetValue(v *DownlinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERChanged(v *DownlinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERChangedValue(v *DownlinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERLegacy(v *DownlinkS1cdma2000tunnelling) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERNewValue(v *DownlinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERPlanned(v *DownlinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERTo(v *DownlinkS1cdma2000tunnelling, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkS1cdma2000tunnellingMethodUnmarshalAPERFrom(v *DownlinkS1cdma2000tunnelling, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkS1cdma2000tunnellingMethodUnmarshalAPERLegacy(v *DownlinkS1cdma2000tunnelling, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDownlinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(v *DownlinkS1cdma2000tunnelling, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldCapture(v *DownlinkS1cdma2000tunnellingValueCodec) *func(DownlinkS1cdma2000tunnelling, aper.DecodeState) (DownlinkS1cdma2000tunnelling, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldCompare(v *DownlinkS1cdma2000tunnellingValueCodec) *func(DownlinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldContext(v *DownlinkS1cdma2000tunnellingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldDecode(v *DownlinkS1cdma2000tunnellingValueCodec) *func([]byte, aper.DecodeState) (DownlinkS1cdma2000tunnelling, error) {
	return &v.decode
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldEncode(v *DownlinkS1cdma2000tunnellingValueCodec) *func(DownlinkS1cdma2000tunnelling, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecFieldPath(v *DownlinkS1cdma2000tunnellingValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecMethodEncodeBudgetValue(v DownlinkS1cdma2000tunnellingValueCodec, a0 DownlinkS1cdma2000tunnelling, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkS1cdma2000tunnellingValueCodecMethodEncodeChanged(v DownlinkS1cdma2000tunnellingValueCodec, a0 DownlinkS1cdma2000tunnelling, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestAPERValueFieldContext(v *ERABModifyRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestAPERValueFieldReceived(v *ERABModifyRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestAPERValueFieldReplay(v *ERABModifyRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestAPERValueFieldWithoutReplay(v *ERABModifyRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestENBUES1APIDIEBindingFieldCodec(v *ERABModifyRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModifyRequestENBUES1APIDIEBindingFieldGet(v *ERABModifyRequestENBUES1APIDIEBinding) *func(*ERABModifyRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABModifyRequestENBUES1APIDIEBindingFieldInfo(v *ERABModifyRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyRequestENBUES1APIDIEBindingFieldInject(v *ERABModifyRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABModifyRequestIEValue {
	return &v.inject
}
func BridgeERABModifyRequestERABToBeModifiedListBearerModReqIEBindingFieldCodec(v *ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) *s25.ERABToBeModifiedListBearerModReqValueCodec {
	return &v.codec
}
func BridgeERABModifyRequestERABToBeModifiedListBearerModReqIEBindingFieldGet(v *ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) *func(*ERABModifyRequestIEValue) (*s25.ERABToBeModifiedListBearerModReq, bool) {
	return &v.get
}
func BridgeERABModifyRequestERABToBeModifiedListBearerModReqIEBindingFieldInfo(v *ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyRequestERABToBeModifiedListBearerModReqIEBindingFieldInject(v *ERABModifyRequestERABToBeModifiedListBearerModReqIEBinding) *func(s25.ERABToBeModifiedListBearerModReq) ERABModifyRequestIEValue {
	return &v.inject
}
func BridgeERABModifyRequestFieldExtCount(v *ERABModifyRequest) *int64   { return &v.extCount }
func BridgeERABModifyRequestFieldExtData(v *ERABModifyRequest) *[][]byte { return &v.extData }
func BridgeERABModifyRequestFieldExtOrigin(v *ERABModifyRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABModifyRequestFieldExtPresent(v *ERABModifyRequest) *[]bool       { return &v.extPresent }
func BridgeERABModifyRequestFieldExtWire(v *ERABModifyRequest) *[]aper.WireSpan { return &v.extWire }
func BridgeERABModifyRequestFieldPerExtPadding(v *ERABModifyRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABModifyRequestFieldPerPadding(v *ERABModifyRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModifyRequestFieldProtocolIEsIndef(v *ERABModifyRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABModifyRequestFieldReceived(v *ERABModifyRequest) *bool { return &v.received }
func BridgeERABModifyRequestFieldReceivedAbsolute(v *ERABModifyRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyRequestFieldReceivedBytes(v *ERABModifyRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyRequestFieldReceivedLocation(v *ERABModifyRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyRequestFieldReplay(v *ERABModifyRequest) *aper.Snapshot { return &v.replay }
func BridgeERABModifyRequestFieldStream(v *ERABModifyRequest) *aper.WireSpan { return &v.stream }
func BridgeERABModifyRequestFieldWithoutReplay(v *ERABModifyRequest) *bool   { return &v.withoutReplay }
func BridgeERABModifyRequestIEContainerAPERValueFieldContext(v *ERABModifyRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEContainerAPERValueFieldReceived(v *ERABModifyRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEContainerAPERValueFieldReplay(v *ERABModifyRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEContainerAPERValueFieldWithoutReplay(v *ERABModifyRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEContainerValueCodecFieldCapture(v *ERABModifyRequestIEContainerValueCodec) *func(ERABModifyRequestIEContainer, aper.DecodeState) (ERABModifyRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestIEContainerValueCodecFieldCompare(v *ERABModifyRequestIEContainerValueCodec) *func(ERABModifyRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestIEContainerValueCodecFieldContext(v *ERABModifyRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEContainerValueCodecFieldDecode(v *ERABModifyRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequestIEContainer, error) {
	return &v.decode
}
func BridgeERABModifyRequestIEContainerValueCodecFieldEncode(v *ERABModifyRequestIEContainerValueCodec) *func(ERABModifyRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestIEContainerValueCodecFieldPath(v *ERABModifyRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestIEContainerValueCodecMethodEncodeBudgetValue(v ERABModifyRequestIEContainerValueCodec, a0 ERABModifyRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestIEContainerValueCodecMethodEncodeChanged(v ERABModifyRequestIEContainerValueCodec, a0 ERABModifyRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestIEFieldAPERValueFieldContext(v *ERABModifyRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEFieldAPERValueFieldReceived(v *ERABModifyRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEFieldAPERValueFieldReplay(v *ERABModifyRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEFieldAPERValueFieldWithoutReplay(v *ERABModifyRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEFieldFieldReceived(v *ERABModifyRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModifyRequestIEFieldFieldReplay(v *ERABModifyRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEFieldFieldStream(v *ERABModifyRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyRequestIEFieldFieldWithoutReplay(v *ERABModifyRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEFieldMethodMarshalAPERTo(v *ERABModifyRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyRequestIEFieldMethodUnmarshalAPERFrom(v *ERABModifyRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyRequestIEFieldValueCodecFieldCapture(v *ERABModifyRequestIEFieldValueCodec) *func(ERABModifyRequestIEField, aper.DecodeState) (ERABModifyRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestIEFieldValueCodecFieldCompare(v *ERABModifyRequestIEFieldValueCodec) *func(ERABModifyRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestIEFieldValueCodecFieldContext(v *ERABModifyRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEFieldValueCodecFieldDecode(v *ERABModifyRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequestIEField, error) {
	return &v.decode
}
func BridgeERABModifyRequestIEFieldValueCodecFieldEncode(v *ERABModifyRequestIEFieldValueCodec) *func(ERABModifyRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestIEFieldValueCodecFieldPath(v *ERABModifyRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestIEFieldValueCodecMethodEncodeBudgetValue(v ERABModifyRequestIEFieldValueCodec, a0 ERABModifyRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestIEFieldValueCodecMethodEncodeChanged(v ERABModifyRequestIEFieldValueCodec, a0 ERABModifyRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestIETableMethodInfoENBUES1APID(v ERABModifyRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABModifyRequestIETableMethodInfoERABToBeModifiedListBearerModReq(v ERABModifyRequestIETable) s00.FieldInfo {
	return v.infoERABToBeModifiedListBearerModReq()
}
func BridgeERABModifyRequestIETableMethodInfoMMEUES1APID(v ERABModifyRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABModifyRequestIETableMethodInfoSecondaryRATDataUsageRequest(v ERABModifyRequestIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageRequest()
}
func BridgeERABModifyRequestIETableMethodInfoUEaggregateMaximumBitrate(v ERABModifyRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeERABModifyRequestIEValueERABIEContainerListAPERValueFieldContext(v *ERABModifyRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModifyRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModifyRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *func(ERABModifyRequestIEValueERABIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *func(ERABModifyRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldContext(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *func(ERABModifyRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecFieldPath(v *ERABModifyRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyRequestIEValueERABIEContainerListValueCodec, a0 ERABModifyRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModifyRequestIEValueERABIEContainerListValueCodec, a0 ERABModifyRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestIEValueFieldId(v *ERABModifyRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModifyRequestIEValueFieldIsOpaque(v *ERABModifyRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModifyRequestIEValueFieldOpaque(v *ERABModifyRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModifyRequestIEValueFieldReceived(v *ERABModifyRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEValueFieldReplay(v *ERABModifyRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEValueFieldRowENBUES1APID(v *ERABModifyRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABModifyRequestIEValueFieldRowERABToBeModifiedListBearerModReq(v *ERABModifyRequestIEValue) **s25.ERABToBeModifiedListBearerModReq {
	return &v.rowERABToBeModifiedListBearerModReq
}
func BridgeERABModifyRequestIEValueFieldRowMMEUES1APID(v *ERABModifyRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABModifyRequestIEValueFieldRowSecondaryRATDataUsageRequest(v *ERABModifyRequestIEValue) **s00.SecondaryRATDataUsageRequest {
	return &v.rowSecondaryRATDataUsageRequest
}
func BridgeERABModifyRequestIEValueFieldRowUEaggregateMaximumBitrate(v *ERABModifyRequestIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeERABModifyRequestIEValueMethodCaptureSemantics(v ERABModifyRequestIEValue, a0 aper.SemanticCapture) ERABModifyRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModifyRequestIEValueMethodCompareSemantics(v ERABModifyRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModifyRequestIEValueMethodDecode(v ERABModifyRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModifyRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModifyRequestIEValueMethodEncode(v ERABModifyRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModifyRequestIEValueMethodEncodeFresh(v ERABModifyRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModifyRequestIEValueMethodMatchesID(v ERABModifyRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModifyRequestIEValueMethodReason(v ERABModifyRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModifyRequestIEValueMethodRule(v ERABModifyRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModifyRequestIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModifyRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModifyRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModifyRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *func(ERABModifyRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModifyRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyRequestIEValueProtocolIEContainerListValueCodec, a0 ERABModifyRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModifyRequestIEValueProtocolIEContainerListValueCodec, a0 ERABModifyRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyRequestMMEUES1APIDIEBindingFieldCodec(v *ERABModifyRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModifyRequestMMEUES1APIDIEBindingFieldGet(v *ERABModifyRequestMMEUES1APIDIEBinding) *func(*ERABModifyRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABModifyRequestMMEUES1APIDIEBindingFieldInfo(v *ERABModifyRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyRequestMMEUES1APIDIEBindingFieldInject(v *ERABModifyRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABModifyRequestIEValue {
	return &v.inject
}
func BridgeERABModifyRequestMethodMarshalAPERBudget(v *ERABModifyRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyRequestMethodMarshalAPERBudgetValue(v *ERABModifyRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModifyRequestMethodMarshalAPERChanged(v *ERABModifyRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModifyRequestMethodMarshalAPERChangedValue(v *ERABModifyRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModifyRequestMethodMarshalAPERLegacy(v *ERABModifyRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModifyRequestMethodMarshalAPERNewValue(v *ERABModifyRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModifyRequestMethodMarshalAPERPlanned(v *ERABModifyRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModifyRequestMethodMarshalAPERTo(v *ERABModifyRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyRequestMethodUnmarshalAPERFrom(v *ERABModifyRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyRequestMethodUnmarshalAPERLegacy(v *ERABModifyRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModifyRequestMethodUnmarshalAPERWithOptions(v *ERABModifyRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModifyRequestSecondaryRATDataUsageRequestIEBindingFieldCodec(v *ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) *s01.SecondaryRATDataUsageRequestValueCodec {
	return &v.codec
}
func BridgeERABModifyRequestSecondaryRATDataUsageRequestIEBindingFieldGet(v *ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) *func(*ERABModifyRequestIEValue) (*s00.SecondaryRATDataUsageRequest, bool) {
	return &v.get
}
func BridgeERABModifyRequestSecondaryRATDataUsageRequestIEBindingFieldInfo(v *ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyRequestSecondaryRATDataUsageRequestIEBindingFieldInject(v *ERABModifyRequestSecondaryRATDataUsageRequestIEBinding) *func(s00.SecondaryRATDataUsageRequest) ERABModifyRequestIEValue {
	return &v.inject
}
func BridgeERABModifyRequestUEAggregateMaximumBitrateIEBindingFieldCodec(v *ERABModifyRequestUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeERABModifyRequestUEAggregateMaximumBitrateIEBindingFieldGet(v *ERABModifyRequestUEAggregateMaximumBitrateIEBinding) *func(*ERABModifyRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeERABModifyRequestUEAggregateMaximumBitrateIEBindingFieldInfo(v *ERABModifyRequestUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyRequestUEAggregateMaximumBitrateIEBindingFieldInject(v *ERABModifyRequestUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) ERABModifyRequestIEValue {
	return &v.inject
}
func BridgeERABModifyRequestValueCodecFieldCapture(v *ERABModifyRequestValueCodec) *func(ERABModifyRequest, aper.DecodeState) (ERABModifyRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyRequestValueCodecFieldCompare(v *ERABModifyRequestValueCodec) *func(ERABModifyRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyRequestValueCodecFieldContext(v *ERABModifyRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyRequestValueCodecFieldDecode(v *ERABModifyRequestValueCodec) *func([]byte, aper.DecodeState) (ERABModifyRequest, error) {
	return &v.decode
}
func BridgeERABModifyRequestValueCodecFieldEncode(v *ERABModifyRequestValueCodec) *func(ERABModifyRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyRequestValueCodecFieldPath(v *ERABModifyRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyRequestValueCodecMethodEncodeBudgetValue(v ERABModifyRequestValueCodec, a0 ERABModifyRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyRequestValueCodecMethodEncodeChanged(v ERABModifyRequestValueCodec, a0 ERABModifyRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestAPERValueFieldContext(v *ERABSetupRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestAPERValueFieldReceived(v *ERABSetupRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestAPERValueFieldReplay(v *ERABSetupRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestAPERValueFieldWithoutReplay(v *ERABSetupRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestENBUES1APIDIEBindingFieldCodec(v *ERABSetupRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABSetupRequestENBUES1APIDIEBindingFieldGet(v *ERABSetupRequestENBUES1APIDIEBinding) *func(*ERABSetupRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABSetupRequestENBUES1APIDIEBindingFieldInfo(v *ERABSetupRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupRequestENBUES1APIDIEBindingFieldInject(v *ERABSetupRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABSetupRequestIEValue {
	return &v.inject
}
func BridgeERABSetupRequestERABToBeSetupListBearerSUReqIEBindingFieldCodec(v *ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) *s29.ERABToBeSetupListBearerSUReqValueCodec {
	return &v.codec
}
func BridgeERABSetupRequestERABToBeSetupListBearerSUReqIEBindingFieldGet(v *ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) *func(*ERABSetupRequestIEValue) (*s29.ERABToBeSetupListBearerSUReq, bool) {
	return &v.get
}
func BridgeERABSetupRequestERABToBeSetupListBearerSUReqIEBindingFieldInfo(v *ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupRequestERABToBeSetupListBearerSUReqIEBindingFieldInject(v *ERABSetupRequestERABToBeSetupListBearerSUReqIEBinding) *func(s29.ERABToBeSetupListBearerSUReq) ERABSetupRequestIEValue {
	return &v.inject
}
func BridgeERABSetupRequestFieldExtCount(v *ERABSetupRequest) *int64   { return &v.extCount }
func BridgeERABSetupRequestFieldExtData(v *ERABSetupRequest) *[][]byte { return &v.extData }
func BridgeERABSetupRequestFieldExtOrigin(v *ERABSetupRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABSetupRequestFieldExtPresent(v *ERABSetupRequest) *[]bool       { return &v.extPresent }
func BridgeERABSetupRequestFieldExtWire(v *ERABSetupRequest) *[]aper.WireSpan { return &v.extWire }
func BridgeERABSetupRequestFieldPerExtPadding(v *ERABSetupRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABSetupRequestFieldPerPadding(v *ERABSetupRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSetupRequestFieldProtocolIEsIndef(v *ERABSetupRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABSetupRequestFieldReceived(v *ERABSetupRequest) *bool { return &v.received }
func BridgeERABSetupRequestFieldReceivedAbsolute(v *ERABSetupRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupRequestFieldReceivedBytes(v *ERABSetupRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupRequestFieldReceivedLocation(v *ERABSetupRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupRequestFieldReplay(v *ERABSetupRequest) *aper.Snapshot { return &v.replay }
func BridgeERABSetupRequestFieldStream(v *ERABSetupRequest) *aper.WireSpan { return &v.stream }
func BridgeERABSetupRequestFieldWithoutReplay(v *ERABSetupRequest) *bool   { return &v.withoutReplay }
func BridgeERABSetupRequestIEContainerAPERValueFieldContext(v *ERABSetupRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEContainerAPERValueFieldReceived(v *ERABSetupRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEContainerAPERValueFieldReplay(v *ERABSetupRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEContainerAPERValueFieldWithoutReplay(v *ERABSetupRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEContainerValueCodecFieldCapture(v *ERABSetupRequestIEContainerValueCodec) *func(ERABSetupRequestIEContainer, aper.DecodeState) (ERABSetupRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestIEContainerValueCodecFieldCompare(v *ERABSetupRequestIEContainerValueCodec) *func(ERABSetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestIEContainerValueCodecFieldContext(v *ERABSetupRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEContainerValueCodecFieldDecode(v *ERABSetupRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequestIEContainer, error) {
	return &v.decode
}
func BridgeERABSetupRequestIEContainerValueCodecFieldEncode(v *ERABSetupRequestIEContainerValueCodec) *func(ERABSetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestIEContainerValueCodecFieldPath(v *ERABSetupRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestIEContainerValueCodecMethodEncodeBudgetValue(v ERABSetupRequestIEContainerValueCodec, a0 ERABSetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestIEContainerValueCodecMethodEncodeChanged(v ERABSetupRequestIEContainerValueCodec, a0 ERABSetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestIEFieldAPERValueFieldContext(v *ERABSetupRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEFieldAPERValueFieldReceived(v *ERABSetupRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEFieldAPERValueFieldReplay(v *ERABSetupRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEFieldAPERValueFieldWithoutReplay(v *ERABSetupRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEFieldFieldReceived(v *ERABSetupRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABSetupRequestIEFieldFieldReplay(v *ERABSetupRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEFieldFieldStream(v *ERABSetupRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupRequestIEFieldFieldWithoutReplay(v *ERABSetupRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEFieldMethodMarshalAPERTo(v *ERABSetupRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupRequestIEFieldMethodUnmarshalAPERFrom(v *ERABSetupRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupRequestIEFieldValueCodecFieldCapture(v *ERABSetupRequestIEFieldValueCodec) *func(ERABSetupRequestIEField, aper.DecodeState) (ERABSetupRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestIEFieldValueCodecFieldCompare(v *ERABSetupRequestIEFieldValueCodec) *func(ERABSetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestIEFieldValueCodecFieldContext(v *ERABSetupRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEFieldValueCodecFieldDecode(v *ERABSetupRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequestIEField, error) {
	return &v.decode
}
func BridgeERABSetupRequestIEFieldValueCodecFieldEncode(v *ERABSetupRequestIEFieldValueCodec) *func(ERABSetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestIEFieldValueCodecFieldPath(v *ERABSetupRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestIEFieldValueCodecMethodEncodeBudgetValue(v ERABSetupRequestIEFieldValueCodec, a0 ERABSetupRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestIEFieldValueCodecMethodEncodeChanged(v ERABSetupRequestIEFieldValueCodec, a0 ERABSetupRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestIETableMethodInfoENBUES1APID(v ERABSetupRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABSetupRequestIETableMethodInfoERABToBeSetupListBearerSUReq(v ERABSetupRequestIETable) s00.FieldInfo {
	return v.infoERABToBeSetupListBearerSUReq()
}
func BridgeERABSetupRequestIETableMethodInfoMMEUES1APID(v ERABSetupRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABSetupRequestIETableMethodInfoUEaggregateMaximumBitrate(v ERABSetupRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeERABSetupRequestIEValueERABIEContainerListAPERValueFieldContext(v *ERABSetupRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueERABIEContainerListAPERValueFieldReceived(v *ERABSetupRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEValueERABIEContainerListAPERValueFieldReplay(v *ERABSetupRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldCapture(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *func(ERABSetupRequestIEValueERABIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldCompare(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *func(ERABSetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldContext(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldDecode(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldEncode(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *func(ERABSetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecFieldPath(v *ERABSetupRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupRequestIEValueERABIEContainerListValueCodec, a0 ERABSetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABSetupRequestIEValueERABIEContainerListValueCodec, a0 ERABSetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestIEValueFieldId(v *ERABSetupRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeERABSetupRequestIEValueFieldIsOpaque(v *ERABSetupRequestIEValue) *bool       { return &v.isOpaque }
func BridgeERABSetupRequestIEValueFieldOpaque(v *ERABSetupRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABSetupRequestIEValueFieldReceived(v *ERABSetupRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEValueFieldReplay(v *ERABSetupRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEValueFieldRowENBUES1APID(v *ERABSetupRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABSetupRequestIEValueFieldRowERABToBeSetupListBearerSUReq(v *ERABSetupRequestIEValue) **s29.ERABToBeSetupListBearerSUReq {
	return &v.rowERABToBeSetupListBearerSUReq
}
func BridgeERABSetupRequestIEValueFieldRowMMEUES1APID(v *ERABSetupRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(v *ERABSetupRequestIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeERABSetupRequestIEValueMethodCaptureSemantics(v ERABSetupRequestIEValue, a0 aper.SemanticCapture) ERABSetupRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABSetupRequestIEValueMethodCompareSemantics(v ERABSetupRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABSetupRequestIEValueMethodDecode(v ERABSetupRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABSetupRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABSetupRequestIEValueMethodEncode(v ERABSetupRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABSetupRequestIEValueMethodEncodeFresh(v ERABSetupRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABSetupRequestIEValueMethodMatchesID(v ERABSetupRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABSetupRequestIEValueMethodReason(v ERABSetupRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABSetupRequestIEValueMethodRule(v ERABSetupRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABSetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABSetupRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABSetupRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABSetupRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *func(ERABSetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABSetupRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupRequestIEValueProtocolIEContainerListValueCodec, a0 ERABSetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABSetupRequestIEValueProtocolIEContainerListValueCodec, a0 ERABSetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupRequestMMEUES1APIDIEBindingFieldCodec(v *ERABSetupRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABSetupRequestMMEUES1APIDIEBindingFieldGet(v *ERABSetupRequestMMEUES1APIDIEBinding) *func(*ERABSetupRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABSetupRequestMMEUES1APIDIEBindingFieldInfo(v *ERABSetupRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupRequestMMEUES1APIDIEBindingFieldInject(v *ERABSetupRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABSetupRequestIEValue {
	return &v.inject
}
func BridgeERABSetupRequestMethodMarshalAPERBudget(v *ERABSetupRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupRequestMethodMarshalAPERBudgetValue(v *ERABSetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupRequestMethodMarshalAPERChanged(v *ERABSetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupRequestMethodMarshalAPERChangedValue(v *ERABSetupRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupRequestMethodMarshalAPERLegacy(v *ERABSetupRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupRequestMethodMarshalAPERNewValue(v *ERABSetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupRequestMethodMarshalAPERPlanned(v *ERABSetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupRequestMethodMarshalAPERTo(v *ERABSetupRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupRequestMethodUnmarshalAPERFrom(v *ERABSetupRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupRequestMethodUnmarshalAPERLegacy(v *ERABSetupRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupRequestMethodUnmarshalAPERWithOptions(v *ERABSetupRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupRequestUEAggregateMaximumBitrateIEBindingFieldCodec(v *ERABSetupRequestUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeERABSetupRequestUEAggregateMaximumBitrateIEBindingFieldGet(v *ERABSetupRequestUEAggregateMaximumBitrateIEBinding) *func(*ERABSetupRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeERABSetupRequestUEAggregateMaximumBitrateIEBindingFieldInfo(v *ERABSetupRequestUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupRequestUEAggregateMaximumBitrateIEBindingFieldInject(v *ERABSetupRequestUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) ERABSetupRequestIEValue {
	return &v.inject
}
func BridgeERABSetupRequestValueCodecFieldCapture(v *ERABSetupRequestValueCodec) *func(ERABSetupRequest, aper.DecodeState) (ERABSetupRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupRequestValueCodecFieldCompare(v *ERABSetupRequestValueCodec) *func(ERABSetupRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupRequestValueCodecFieldContext(v *ERABSetupRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupRequestValueCodecFieldDecode(v *ERABSetupRequestValueCodec) *func([]byte, aper.DecodeState) (ERABSetupRequest, error) {
	return &v.decode
}
func BridgeERABSetupRequestValueCodecFieldEncode(v *ERABSetupRequestValueCodec) *func(ERABSetupRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupRequestValueCodecFieldPath(v *ERABSetupRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupRequestValueCodecMethodEncodeBudgetValue(v ERABSetupRequestValueCodec, a0 ERABSetupRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupRequestValueCodecMethodEncodeChanged(v ERABSetupRequestValueCodec, a0 ERABSetupRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldPerPadding(v *ERABToBeModifiedListBearerModIndComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldReceived(v *ERABToBeModifiedListBearerModIndComplete) *bool {
	return &v.received
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldReceivedAbsolute(v *ERABToBeModifiedListBearerModIndComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldReceivedBytes(v *ERABToBeModifiedListBearerModIndComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldReceivedLocation(v *ERABToBeModifiedListBearerModIndComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldReplay(v *ERABToBeModifiedListBearerModIndComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldStream(v *ERABToBeModifiedListBearerModIndComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifiedListBearerModIndCompleteFieldWithoutReplay(v *ERABToBeModifiedListBearerModIndComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudget(v *ERABToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudgetValue(v *ERABToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERChanged(v *ERABToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERChangedValue(v *ERABToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERLegacy(v *ERABToBeModifiedListBearerModIndComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERNewValue(v *ERABToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERPlanned(v *ERABToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodUnmarshalAPERLegacy(v *ERABToBeModifiedListBearerModIndComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeModifiedListBearerModIndCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeModifiedListBearerModIndComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldPerPadding(v *ERABToBeModifiedListBearerModReqComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldReceived(v *ERABToBeModifiedListBearerModReqComplete) *bool {
	return &v.received
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldReceivedAbsolute(v *ERABToBeModifiedListBearerModReqComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldReceivedBytes(v *ERABToBeModifiedListBearerModReqComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldReceivedLocation(v *ERABToBeModifiedListBearerModReqComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldReplay(v *ERABToBeModifiedListBearerModReqComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldStream(v *ERABToBeModifiedListBearerModReqComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifiedListBearerModReqCompleteFieldWithoutReplay(v *ERABToBeModifiedListBearerModReqComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERBudget(v *ERABToBeModifiedListBearerModReqComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERBudgetValue(v *ERABToBeModifiedListBearerModReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERChanged(v *ERABToBeModifiedListBearerModReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERChangedValue(v *ERABToBeModifiedListBearerModReqComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERLegacy(v *ERABToBeModifiedListBearerModReqComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERNewValue(v *ERABToBeModifiedListBearerModReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodMarshalAPERPlanned(v *ERABToBeModifiedListBearerModReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodUnmarshalAPERLegacy(v *ERABToBeModifiedListBearerModReqComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeModifiedListBearerModReqCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeModifiedListBearerModReqComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldPerPadding(v *ERABToBeSetupListBearerSUReqComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldReceived(v *ERABToBeSetupListBearerSUReqComplete) *bool {
	return &v.received
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldReceivedAbsolute(v *ERABToBeSetupListBearerSUReqComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldReceivedBytes(v *ERABToBeSetupListBearerSUReqComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldReceivedLocation(v *ERABToBeSetupListBearerSUReqComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldReplay(v *ERABToBeSetupListBearerSUReqComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldStream(v *ERABToBeSetupListBearerSUReqComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupListBearerSUReqCompleteFieldWithoutReplay(v *ERABToBeSetupListBearerSUReqComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERBudget(v *ERABToBeSetupListBearerSUReqComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERBudgetValue(v *ERABToBeSetupListBearerSUReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERChanged(v *ERABToBeSetupListBearerSUReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERChangedValue(v *ERABToBeSetupListBearerSUReqComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERLegacy(v *ERABToBeSetupListBearerSUReqComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERNewValue(v *ERABToBeSetupListBearerSUReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodMarshalAPERPlanned(v *ERABToBeSetupListBearerSUReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodUnmarshalAPERLegacy(v *ERABToBeSetupListBearerSUReqComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupListBearerSUReqCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeSetupListBearerSUReqComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldPerPadding(v *ERABToBeSetupListCtxtSUReqComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldReceived(v *ERABToBeSetupListCtxtSUReqComplete) *bool {
	return &v.received
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldReceivedAbsolute(v *ERABToBeSetupListCtxtSUReqComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldReceivedBytes(v *ERABToBeSetupListCtxtSUReqComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldReceivedLocation(v *ERABToBeSetupListCtxtSUReqComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldReplay(v *ERABToBeSetupListCtxtSUReqComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldStream(v *ERABToBeSetupListCtxtSUReqComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupListCtxtSUReqCompleteFieldWithoutReplay(v *ERABToBeSetupListCtxtSUReqComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERBudget(v *ERABToBeSetupListCtxtSUReqComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERBudgetValue(v *ERABToBeSetupListCtxtSUReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERChanged(v *ERABToBeSetupListCtxtSUReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERChangedValue(v *ERABToBeSetupListCtxtSUReqComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERLegacy(v *ERABToBeSetupListCtxtSUReqComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERNewValue(v *ERABToBeSetupListCtxtSUReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERPlanned(v *ERABToBeSetupListCtxtSUReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodUnmarshalAPERLegacy(v *ERABToBeSetupListCtxtSUReqComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupListCtxtSUReqCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeSetupListCtxtSUReqComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSetupListHOReqCompleteFieldPerPadding(v *ERABToBeSetupListHOReqComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeSetupListHOReqCompleteFieldReceived(v *ERABToBeSetupListHOReqComplete) *bool {
	return &v.received
}
func BridgeERABToBeSetupListHOReqCompleteFieldReceivedAbsolute(v *ERABToBeSetupListHOReqComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSetupListHOReqCompleteFieldReceivedBytes(v *ERABToBeSetupListHOReqComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSetupListHOReqCompleteFieldReceivedLocation(v *ERABToBeSetupListHOReqComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSetupListHOReqCompleteFieldReplay(v *ERABToBeSetupListHOReqComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupListHOReqCompleteFieldStream(v *ERABToBeSetupListHOReqComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupListHOReqCompleteFieldWithoutReplay(v *ERABToBeSetupListHOReqComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERBudget(v *ERABToBeSetupListHOReqComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERBudgetValue(v *ERABToBeSetupListHOReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERChanged(v *ERABToBeSetupListHOReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERChangedValue(v *ERABToBeSetupListHOReqComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERLegacy(v *ERABToBeSetupListHOReqComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERNewValue(v *ERABToBeSetupListHOReqComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERPlanned(v *ERABToBeSetupListHOReqComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSetupListHOReqCompleteMethodUnmarshalAPERLegacy(v *ERABToBeSetupListHOReqComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSetupListHOReqCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeSetupListHOReqComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeSwitchedDLListCompleteFieldPerPadding(v *ERABToBeSwitchedDLListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeSwitchedDLListCompleteFieldReceived(v *ERABToBeSwitchedDLListComplete) *bool {
	return &v.received
}
func BridgeERABToBeSwitchedDLListCompleteFieldReceivedAbsolute(v *ERABToBeSwitchedDLListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSwitchedDLListCompleteFieldReceivedBytes(v *ERABToBeSwitchedDLListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSwitchedDLListCompleteFieldReceivedLocation(v *ERABToBeSwitchedDLListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSwitchedDLListCompleteFieldReplay(v *ERABToBeSwitchedDLListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedDLListCompleteFieldStream(v *ERABToBeSwitchedDLListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedDLListCompleteFieldWithoutReplay(v *ERABToBeSwitchedDLListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERBudget(v *ERABToBeSwitchedDLListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERBudgetValue(v *ERABToBeSwitchedDLListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERChanged(v *ERABToBeSwitchedDLListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERChangedValue(v *ERABToBeSwitchedDLListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERLegacy(v *ERABToBeSwitchedDLListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERNewValue(v *ERABToBeSwitchedDLListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERPlanned(v *ERABToBeSwitchedDLListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSwitchedDLListCompleteMethodUnmarshalAPERLegacy(v *ERABToBeSwitchedDLListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSwitchedDLListCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeSwitchedDLListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverCommandAPERValueFieldContext(v *HandoverCommandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandAPERValueFieldReceived(v *HandoverCommandAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandAPERValueFieldReplay(v *HandoverCommandAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandAPERValueFieldWithoutReplay(v *HandoverCommandAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandCriticalityDiagnosticsIEBindingFieldCodec(v *HandoverCommandCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeHandoverCommandCriticalityDiagnosticsIEBindingFieldGet(v *HandoverCommandCriticalityDiagnosticsIEBinding) *func(*HandoverCommandIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeHandoverCommandCriticalityDiagnosticsIEBindingFieldInfo(v *HandoverCommandCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandCriticalityDiagnosticsIEBindingFieldInject(v *HandoverCommandCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandENBUES1APIDIEBindingFieldCodec(v *HandoverCommandENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCommandENBUES1APIDIEBindingFieldGet(v *HandoverCommandENBUES1APIDIEBinding) *func(*HandoverCommandIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCommandENBUES1APIDIEBindingFieldInfo(v *HandoverCommandENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandENBUES1APIDIEBindingFieldInject(v *HandoverCommandENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandERABListIEBindingFieldCodec(v *HandoverCommandERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeHandoverCommandERABListIEBindingFieldGet(v *HandoverCommandERABListIEBinding) *func(*HandoverCommandIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeHandoverCommandERABListIEBindingFieldInfo(v *HandoverCommandERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandERABListIEBindingFieldInject(v *HandoverCommandERABListIEBinding) *func(s16.ERABList) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandERABSubjecttoDataForwardingListIEBindingFieldCodec(v *HandoverCommandERABSubjecttoDataForwardingListIEBinding) *s16.ERABSubjecttoDataForwardingListValueCodec {
	return &v.codec
}
func BridgeHandoverCommandERABSubjecttoDataForwardingListIEBindingFieldGet(v *HandoverCommandERABSubjecttoDataForwardingListIEBinding) *func(*HandoverCommandIEValue) (*s16.ERABSubjecttoDataForwardingList, bool) {
	return &v.get
}
func BridgeHandoverCommandERABSubjecttoDataForwardingListIEBindingFieldInfo(v *HandoverCommandERABSubjecttoDataForwardingListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandERABSubjecttoDataForwardingListIEBindingFieldInject(v *HandoverCommandERABSubjecttoDataForwardingListIEBinding) *func(s16.ERABSubjecttoDataForwardingList) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandFieldExtCount(v *HandoverCommand) *int64   { return &v.extCount }
func BridgeHandoverCommandFieldExtData(v *HandoverCommand) *[][]byte { return &v.extData }
func BridgeHandoverCommandFieldExtOrigin(v *HandoverCommand) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverCommandFieldExtPresent(v *HandoverCommand) *[]bool       { return &v.extPresent }
func BridgeHandoverCommandFieldExtWire(v *HandoverCommand) *[]aper.WireSpan { return &v.extWire }
func BridgeHandoverCommandFieldPerExtPadding(v *HandoverCommand) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverCommandFieldPerPadding(v *HandoverCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverCommandFieldProtocolIEsIndef(v *HandoverCommand) *bool { return &v.protocolIEsIndef }
func BridgeHandoverCommandFieldReceived(v *HandoverCommand) *bool         { return &v.received }
func BridgeHandoverCommandFieldReceivedAbsolute(v *HandoverCommand) *bool { return &v.receivedAbsolute }
func BridgeHandoverCommandFieldReceivedBytes(v *HandoverCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverCommandFieldReceivedLocation(v *HandoverCommand) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverCommandFieldReplay(v *HandoverCommand) *aper.Snapshot { return &v.replay }
func BridgeHandoverCommandFieldStream(v *HandoverCommand) *aper.WireSpan { return &v.stream }
func BridgeHandoverCommandFieldWithoutReplay(v *HandoverCommand) *bool   { return &v.withoutReplay }
func BridgeHandoverCommandHandoverTypeIEBindingFieldCodec(v *HandoverCommandHandoverTypeIEBinding) *s00.HandoverTypeValueCodec {
	return &v.codec
}
func BridgeHandoverCommandHandoverTypeIEBindingFieldGet(v *HandoverCommandHandoverTypeIEBinding) *func(*HandoverCommandIEValue) (*s00.HandoverType, bool) {
	return &v.get
}
func BridgeHandoverCommandHandoverTypeIEBindingFieldInfo(v *HandoverCommandHandoverTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandHandoverTypeIEBindingFieldInject(v *HandoverCommandHandoverTypeIEBinding) *func(s00.HandoverType) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandIEContainerAPERValueFieldContext(v *HandoverCommandIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEContainerAPERValueFieldReceived(v *HandoverCommandIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEContainerAPERValueFieldReplay(v *HandoverCommandIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEContainerAPERValueFieldWithoutReplay(v *HandoverCommandIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEContainerValueCodecFieldCapture(v *HandoverCommandIEContainerValueCodec) *func(HandoverCommandIEContainer, aper.DecodeState) (HandoverCommandIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandIEContainerValueCodecFieldCompare(v *HandoverCommandIEContainerValueCodec) *func(HandoverCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandIEContainerValueCodecFieldContext(v *HandoverCommandIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEContainerValueCodecFieldDecode(v *HandoverCommandIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverCommandIEContainer, error) {
	return &v.decode
}
func BridgeHandoverCommandIEContainerValueCodecFieldEncode(v *HandoverCommandIEContainerValueCodec) *func(HandoverCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandIEContainerValueCodecFieldPath(v *HandoverCommandIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandIEContainerValueCodecMethodEncodeBudgetValue(v HandoverCommandIEContainerValueCodec, a0 HandoverCommandIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandIEContainerValueCodecMethodEncodeChanged(v HandoverCommandIEContainerValueCodec, a0 HandoverCommandIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCommandIEFieldAPERValueFieldContext(v *HandoverCommandIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEFieldAPERValueFieldReceived(v *HandoverCommandIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEFieldAPERValueFieldReplay(v *HandoverCommandIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEFieldAPERValueFieldWithoutReplay(v *HandoverCommandIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEFieldFieldReceived(v *HandoverCommandIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverCommandIEFieldFieldReplay(v *HandoverCommandIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEFieldFieldStream(v *HandoverCommandIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverCommandIEFieldFieldWithoutReplay(v *HandoverCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEFieldMethodMarshalAPERTo(v *HandoverCommandIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCommandIEFieldMethodUnmarshalAPERFrom(v *HandoverCommandIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCommandIEFieldValueCodecFieldCapture(v *HandoverCommandIEFieldValueCodec) *func(HandoverCommandIEField, aper.DecodeState) (HandoverCommandIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandIEFieldValueCodecFieldCompare(v *HandoverCommandIEFieldValueCodec) *func(HandoverCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandIEFieldValueCodecFieldContext(v *HandoverCommandIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEFieldValueCodecFieldDecode(v *HandoverCommandIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverCommandIEField, error) {
	return &v.decode
}
func BridgeHandoverCommandIEFieldValueCodecFieldEncode(v *HandoverCommandIEFieldValueCodec) *func(HandoverCommandIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandIEFieldValueCodecFieldPath(v *HandoverCommandIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandIEFieldValueCodecMethodEncodeBudgetValue(v HandoverCommandIEFieldValueCodec, a0 HandoverCommandIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandIEFieldValueCodecMethodEncodeChanged(v HandoverCommandIEFieldValueCodec, a0 HandoverCommandIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCommandIETableMethodInfoCriticalityDiagnostics(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeHandoverCommandIETableMethodInfoENBUES1APID(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverCommandIETableMethodInfoERABSubjecttoDataForwardingList(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoERABSubjecttoDataForwardingList()
}
func BridgeHandoverCommandIETableMethodInfoERABtoReleaseListHOCmd(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoERABtoReleaseListHOCmd()
}
func BridgeHandoverCommandIETableMethodInfoHandoverType(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoHandoverType()
}
func BridgeHandoverCommandIETableMethodInfoMMEUES1APID(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverCommandIETableMethodInfoNASSecurityParametersfromEUTRAN(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoNASSecurityParametersfromEUTRAN()
}
func BridgeHandoverCommandIETableMethodInfoTargetToSourceTransparentContainer(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoTargetToSourceTransparentContainer()
}
func BridgeHandoverCommandIETableMethodInfoTargetToSourceTransparentContainerSecondary(v HandoverCommandIETable) s00.FieldInfo {
	return v.infoTargetToSourceTransparentContainerSecondary()
}
func BridgeHandoverCommandIEValueERABIEContainerListAPERValueFieldContext(v *HandoverCommandIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverCommandIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverCommandIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverCommandIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverCommandIEValueERABIEContainerListValueCodec) *func(HandoverCommandIEValueERABIEContainerList, aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverCommandIEValueERABIEContainerListValueCodec) *func(HandoverCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldContext(v *HandoverCommandIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverCommandIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCommandIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverCommandIEValueERABIEContainerListValueCodec) *func(HandoverCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecFieldPath(v *HandoverCommandIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCommandIEValueERABIEContainerListValueCodec, a0 HandoverCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverCommandIEValueERABIEContainerListValueCodec, a0 HandoverCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCommandIEValueFieldId(v *HandoverCommandIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverCommandIEValueFieldIsOpaque(v *HandoverCommandIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverCommandIEValueFieldOpaque(v *HandoverCommandIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverCommandIEValueFieldReceived(v *HandoverCommandIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEValueFieldReplay(v *HandoverCommandIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEValueFieldRowCriticalityDiagnostics(v *HandoverCommandIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeHandoverCommandIEValueFieldRowENBUES1APID(v *HandoverCommandIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverCommandIEValueFieldRowERABSubjecttoDataForwardingList(v *HandoverCommandIEValue) **s16.ERABSubjecttoDataForwardingList {
	return &v.rowERABSubjecttoDataForwardingList
}
func BridgeHandoverCommandIEValueFieldRowERABtoReleaseListHOCmd(v *HandoverCommandIEValue) **s16.ERABList {
	return &v.rowERABtoReleaseListHOCmd
}
func BridgeHandoverCommandIEValueFieldRowHandoverType(v *HandoverCommandIEValue) **s00.HandoverType {
	return &v.rowHandoverType
}
func BridgeHandoverCommandIEValueFieldRowMMEUES1APID(v *HandoverCommandIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverCommandIEValueFieldRowNASSecurityParametersfromEUTRAN(v *HandoverCommandIEValue) **s00.NASSecurityParametersfromEUTRAN {
	return &v.rowNASSecurityParametersfromEUTRAN
}
func BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainer(v *HandoverCommandIEValue) **s00.TargetToSourceTransparentContainer {
	return &v.rowTargetToSourceTransparentContainer
}
func BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainerSecondary(v *HandoverCommandIEValue) **s00.TargetToSourceTransparentContainer {
	return &v.rowTargetToSourceTransparentContainerSecondary
}
func BridgeHandoverCommandIEValueMethodCaptureSemantics(v HandoverCommandIEValue, a0 aper.SemanticCapture) HandoverCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverCommandIEValueMethodCompareSemantics(v HandoverCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverCommandIEValueMethodDecode(v HandoverCommandIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverCommandIEValueMethodEncode(v HandoverCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverCommandIEValueMethodEncodeFresh(v HandoverCommandIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverCommandIEValueMethodMatchesID(v HandoverCommandIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverCommandIEValueMethodReason(v HandoverCommandIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverCommandIEValueMethodRule(v HandoverCommandIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverCommandIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCommandIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverCommandIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCommandIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverCommandIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCommandIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverCommandIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverCommandIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCommandIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverCommandIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCommandIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverCommandIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCommandIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *func(HandoverCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverCommandIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCommandIEValueProtocolIEContainerListValueCodec, a0 HandoverCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverCommandIEValueProtocolIEContainerListValueCodec, a0 HandoverCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCommandMMEUES1APIDIEBindingFieldCodec(v *HandoverCommandMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCommandMMEUES1APIDIEBindingFieldGet(v *HandoverCommandMMEUES1APIDIEBinding) *func(*HandoverCommandIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCommandMMEUES1APIDIEBindingFieldInfo(v *HandoverCommandMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandMMEUES1APIDIEBindingFieldInject(v *HandoverCommandMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandMethodMarshalAPERBudget(v *HandoverCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverCommandMethodMarshalAPERBudgetValue(v *HandoverCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverCommandMethodMarshalAPERChanged(v *HandoverCommand, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverCommandMethodMarshalAPERChangedValue(v *HandoverCommand, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverCommandMethodMarshalAPERLegacy(v *HandoverCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverCommandMethodMarshalAPERNewValue(v *HandoverCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverCommandMethodMarshalAPERPlanned(v *HandoverCommand, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverCommandMethodMarshalAPERTo(v *HandoverCommand, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCommandMethodUnmarshalAPERFrom(v *HandoverCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCommandMethodUnmarshalAPERLegacy(v *HandoverCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverCommandMethodUnmarshalAPERWithOptions(v *HandoverCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverCommandNASSecurityParametersfromEUTRANIEBindingFieldCodec(v *HandoverCommandNASSecurityParametersfromEUTRANIEBinding) *s01.NASSecurityParametersfromEUTRANValueCodec {
	return &v.codec
}
func BridgeHandoverCommandNASSecurityParametersfromEUTRANIEBindingFieldGet(v *HandoverCommandNASSecurityParametersfromEUTRANIEBinding) *func(*HandoverCommandIEValue) (*s00.NASSecurityParametersfromEUTRAN, bool) {
	return &v.get
}
func BridgeHandoverCommandNASSecurityParametersfromEUTRANIEBindingFieldInfo(v *HandoverCommandNASSecurityParametersfromEUTRANIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandNASSecurityParametersfromEUTRANIEBindingFieldInject(v *HandoverCommandNASSecurityParametersfromEUTRANIEBinding) *func(s00.NASSecurityParametersfromEUTRAN) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandTargetToSourceTransparentContainerIEBindingFieldCodec(v *HandoverCommandTargetToSourceTransparentContainerIEBinding) *s01.TargetToSourceTransparentContainerValueCodec {
	return &v.codec
}
func BridgeHandoverCommandTargetToSourceTransparentContainerIEBindingFieldGet(v *HandoverCommandTargetToSourceTransparentContainerIEBinding) *func(*HandoverCommandIEValue) (*s00.TargetToSourceTransparentContainer, bool) {
	return &v.get
}
func BridgeHandoverCommandTargetToSourceTransparentContainerIEBindingFieldInfo(v *HandoverCommandTargetToSourceTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCommandTargetToSourceTransparentContainerIEBindingFieldInject(v *HandoverCommandTargetToSourceTransparentContainerIEBinding) *func(s00.TargetToSourceTransparentContainer) HandoverCommandIEValue {
	return &v.inject
}
func BridgeHandoverCommandValueCodecFieldCapture(v *HandoverCommandValueCodec) *func(HandoverCommand, aper.DecodeState) (HandoverCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandValueCodecFieldCompare(v *HandoverCommandValueCodec) *func(HandoverCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandValueCodecFieldContext(v *HandoverCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandValueCodecFieldDecode(v *HandoverCommandValueCodec) *func([]byte, aper.DecodeState) (HandoverCommand, error) {
	return &v.decode
}
func BridgeHandoverCommandValueCodecFieldEncode(v *HandoverCommandValueCodec) *func(HandoverCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandValueCodecFieldPath(v *HandoverCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCommandValueCodecMethodEncodeBudgetValue(v HandoverCommandValueCodec, a0 HandoverCommand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCommandValueCodecMethodEncodeChanged(v HandoverCommandValueCodec, a0 HandoverCommand, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestCSGIdIEBindingFieldCodec(v *PathSwitchRequestCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCSGIdIEBindingFieldGet(v *PathSwitchRequestCSGIdIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgePathSwitchRequestCSGIdIEBindingFieldInfo(v *PathSwitchRequestCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCSGIdIEBindingFieldInject(v *PathSwitchRequestCSGIdIEBinding) *func(s00.CSGId) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldCodec(v *PathSwitchRequestCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldGet(v *PathSwitchRequestCSGMembershipStatusIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldInfo(v *PathSwitchRequestCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldInject(v *PathSwitchRequestCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldCodec(v *PathSwitchRequestCellAccessModeIEBinding) *s00.CellAccessModeValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldGet(v *PathSwitchRequestCellAccessModeIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CellAccessMode, bool) {
	return &v.get
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldInfo(v *PathSwitchRequestCellAccessModeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldInject(v *PathSwitchRequestCellAccessModeIEBinding) *func(s00.CellAccessMode) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldCodec(v *PathSwitchRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldGet(v *PathSwitchRequestENBUES1APIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldInfo(v *PathSwitchRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldInject(v *PathSwitchRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldCodec(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *s30.ERABToBeSwitchedDLListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldGet(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *func(*PathSwitchRequestIEValue) (*s30.ERABToBeSwitchedDLList, bool) {
	return &v.get
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldInfo(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldInject(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *func(s30.ERABToBeSwitchedDLList) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldCodec(v *PathSwitchRequestEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldGet(v *PathSwitchRequestEUTRANCGIIEBinding) *func(*PathSwitchRequestIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldInfo(v *PathSwitchRequestEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldInject(v *PathSwitchRequestEUTRANCGIIEBinding) *func(s17.EUTRANCGI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldCodec(v *PathSwitchRequestGUMMEIIEBinding) *s18.GUMMEIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldGet(v *PathSwitchRequestGUMMEIIEBinding) *func(*PathSwitchRequestIEValue) (*s18.GUMMEI, bool) {
	return &v.get
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldInfo(v *PathSwitchRequestGUMMEIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldInject(v *PathSwitchRequestGUMMEIIEBinding) *func(s18.GUMMEI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestIEContainerAPERValueFieldContext(v *PathSwitchRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEContainerAPERValueFieldReceived(v *PathSwitchRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEContainerAPERValueFieldReplay(v *PathSwitchRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEContainerAPERValueFieldWithoutReplay(v *PathSwitchRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEContainerValueCodecFieldCapture(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, aper.DecodeState) (PathSwitchRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEContainerValueCodecFieldCompare(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEContainerValueCodecFieldContext(v *PathSwitchRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEContainerValueCodecFieldDecode(v *PathSwitchRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEContainer, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEContainerValueCodecFieldEncode(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEContainerValueCodecFieldPath(v *PathSwitchRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEContainerValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEContainerValueCodec, a0 PathSwitchRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEContainerValueCodecMethodEncodeChanged(v PathSwitchRequestIEContainerValueCodec, a0 PathSwitchRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEFieldAPERValueFieldContext(v *PathSwitchRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEFieldAPERValueFieldReceived(v *PathSwitchRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEFieldAPERValueFieldReplay(v *PathSwitchRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEFieldAPERValueFieldWithoutReplay(v *PathSwitchRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEFieldFieldReceived(v *PathSwitchRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePathSwitchRequestIEFieldFieldReplay(v *PathSwitchRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEFieldFieldStream(v *PathSwitchRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestIEFieldFieldWithoutReplay(v *PathSwitchRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEFieldMethodMarshalAPERTo(v *PathSwitchRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestIEFieldMethodUnmarshalAPERFrom(v *PathSwitchRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestIEFieldValueCodecFieldCapture(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, aper.DecodeState) (PathSwitchRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEFieldValueCodecFieldCompare(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEFieldValueCodecFieldContext(v *PathSwitchRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEFieldValueCodecFieldDecode(v *PathSwitchRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEField, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEFieldValueCodecFieldEncode(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEFieldValueCodecFieldPath(v *PathSwitchRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEFieldValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEFieldValueCodec, a0 PathSwitchRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEFieldValueCodecMethodEncodeChanged(v PathSwitchRequestIEFieldValueCodec, a0 PathSwitchRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEValueFieldId(v *PathSwitchRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePathSwitchRequestIEValueFieldIsOpaque(v *PathSwitchRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgePathSwitchRequestIEValueFieldOpaque(v *PathSwitchRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePathSwitchRequestIEValueFieldReceived(v *PathSwitchRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueFieldReplay(v *PathSwitchRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueFieldRowCSGId(v *PathSwitchRequestIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgePathSwitchRequestIEValueFieldRowCSGMembershipStatus(v *PathSwitchRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgePathSwitchRequestIEValueFieldRowCellAccessMode(v *PathSwitchRequestIEValue) **s00.CellAccessMode {
	return &v.rowCellAccessMode
}
func BridgePathSwitchRequestIEValueFieldRowENBUES1APID(v *PathSwitchRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgePathSwitchRequestIEValueFieldRowERABToBeSwitchedDLList(v *PathSwitchRequestIEValue) **s30.ERABToBeSwitchedDLList {
	return &v.rowERABToBeSwitchedDLList
}
func BridgePathSwitchRequestIEValueFieldRowEUTRANCGI(v *PathSwitchRequestIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgePathSwitchRequestIEValueFieldRowLHNID(v *PathSwitchRequestIEValue) **s00.LHNID {
	return &v.rowLHNID
}
func BridgePathSwitchRequestIEValueFieldRowLTENTNTAIInformation(v *PathSwitchRequestIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgePathSwitchRequestIEValueFieldRowNRUESecurityCapabilities(v *PathSwitchRequestIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgePathSwitchRequestIEValueFieldRowPSCellInformation(v *PathSwitchRequestIEValue) **s20.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgePathSwitchRequestIEValueFieldRowRRCResumeCause(v *PathSwitchRequestIEValue) **s00.RRCEstablishmentCause {
	return &v.rowRRCResumeCause
}
func BridgePathSwitchRequestIEValueFieldRowSourceMMEGUMMEI(v *PathSwitchRequestIEValue) **s18.GUMMEI {
	return &v.rowSourceMMEGUMMEI
}
func BridgePathSwitchRequestIEValueFieldRowSourceMMEUES1APID(v *PathSwitchRequestIEValue) **s00.MMEUES1APID {
	return &v.rowSourceMMEUES1APID
}
func BridgePathSwitchRequestIEValueFieldRowTAI(v *PathSwitchRequestIEValue) **s31.TAI {
	return &v.rowTAI
}
func BridgePathSwitchRequestIEValueFieldRowTunnelInformationForBBF(v *PathSwitchRequestIEValue) **s34.TunnelInformation {
	return &v.rowTunnelInformationForBBF
}
func BridgePathSwitchRequestIEValueFieldRowUESecurityCapabilities(v *PathSwitchRequestIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgePathSwitchRequestIEValueMethodCaptureSemantics(v PathSwitchRequestIEValue, a0 aper.SemanticCapture) PathSwitchRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgePathSwitchRequestIEValueMethodCompareSemantics(v PathSwitchRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePathSwitchRequestIEValueMethodDecode(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PathSwitchRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePathSwitchRequestIEValueMethodEncode(v PathSwitchRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePathSwitchRequestIEValueMethodEncodeFresh(v PathSwitchRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePathSwitchRequestIEValueMethodMatchesID(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePathSwitchRequestIEValueMethodReason(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePathSwitchRequestIEValueMethodRule(v PathSwitchRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestLHNIDIEBindingFieldCodec(v *PathSwitchRequestLHNIDIEBinding) *s01.LHNIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestLHNIDIEBindingFieldGet(v *PathSwitchRequestLHNIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.LHNID, bool) {
	return &v.get
}
func BridgePathSwitchRequestLHNIDIEBindingFieldInfo(v *PathSwitchRequestLHNIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestLHNIDIEBindingFieldInject(v *PathSwitchRequestLHNIDIEBinding) *func(s00.LHNID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldCodec(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldGet(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldInfo(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldInject(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldCodec(v *PathSwitchRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldGet(v *PathSwitchRequestMMEUES1APIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldInfo(v *PathSwitchRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldInject(v *PathSwitchRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldCodec(v *PathSwitchRequestPSCellInformationIEBinding) *s20.PSCellInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldGet(v *PathSwitchRequestPSCellInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s20.PSCellInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldInfo(v *PathSwitchRequestPSCellInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldInject(v *PathSwitchRequestPSCellInformationIEBinding) *func(s20.PSCellInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldCodec(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *s01.RRCEstablishmentCauseValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldGet(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *func(*PathSwitchRequestIEValue) (*s00.RRCEstablishmentCause, bool) {
	return &v.get
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldInfo(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldInject(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *func(s00.RRCEstablishmentCause) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestTAIIEBindingFieldCodec(v *PathSwitchRequestTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestTAIIEBindingFieldGet(v *PathSwitchRequestTAIIEBinding) *func(*PathSwitchRequestIEValue) (*s31.TAI, bool) {
	return &v.get
}
func BridgePathSwitchRequestTAIIEBindingFieldInfo(v *PathSwitchRequestTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestTAIIEBindingFieldInject(v *PathSwitchRequestTAIIEBinding) *func(s31.TAI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldCodec(v *PathSwitchRequestTunnelInformationIEBinding) *s35.TunnelInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldGet(v *PathSwitchRequestTunnelInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s34.TunnelInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldInfo(v *PathSwitchRequestTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldInject(v *PathSwitchRequestTunnelInformationIEBinding) *func(s34.TunnelInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) PathSwitchRequestIEValue {
	return &v.inject
}
