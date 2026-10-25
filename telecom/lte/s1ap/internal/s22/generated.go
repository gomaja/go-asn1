// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s22 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s22

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverPreparationFailureIEContainer is the concrete ProtocolIEContainer[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEContainer []HandoverPreparationFailureIEField

// HandoverPreparationFailureIEField is the concrete ProtocolIEField[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverPreparationFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEField) WithoutReplay() HandoverPreparationFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverPreparationFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverPreparationFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverPreparationFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverPreparationFailureIEField{}
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
	var zero HandoverPreparationFailureIEValue

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

// HandoverFailureIEContainer is the concrete ProtocolIEContainer[HandoverFailureIEValue].
type HandoverFailureIEContainer []HandoverFailureIEField

// HandoverFailureIEField is the concrete ProtocolIEField[HandoverFailureIEValue].
type HandoverFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEField) WithoutReplay() HandoverFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverFailureIEField{}
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
	var zero HandoverFailureIEValue

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

// HandoverCancelAcknowledgeIEContainer is the concrete ProtocolIEContainer[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEContainer []HandoverCancelAcknowledgeIEField

// HandoverCancelAcknowledgeIEField is the concrete ProtocolIEField[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverCancelAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEField) WithoutReplay() HandoverCancelAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverCancelAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverCancelAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverCancelAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancelAcknowledgeIEField{}
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
	var zero HandoverCancelAcknowledgeIEValue

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

// InitialContextSetupFailureIEContainer is the concrete ProtocolIEContainer[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEContainer []InitialContextSetupFailureIEField

// InitialContextSetupFailureIEField is the concrete ProtocolIEField[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         InitialContextSetupFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEField) WithoutReplay() InitialContextSetupFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InitialContextSetupFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InitialContextSetupFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *InitialContextSetupFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupFailureIEField{}
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
	var zero InitialContextSetupFailureIEValue

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

// ENBConfigurationUpdateAcknowledgeIEContainer is the concrete ProtocolIEContainer[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEContainer []ENBConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateAcknowledgeIEField is the concrete ProtocolIEField[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBConfigurationUpdateAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEField) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBConfigurationUpdateAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBConfigurationUpdateAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBConfigurationUpdateAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateAcknowledgeIEField{}
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
	var zero ENBConfigurationUpdateAcknowledgeIEValue

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

// ENBConfigurationUpdateFailureIEContainer is the concrete ProtocolIEContainer[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEContainer []ENBConfigurationUpdateFailureIEField

// ENBConfigurationUpdateFailureIEField is the concrete ProtocolIEField[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBConfigurationUpdateFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEField) WithoutReplay() ENBConfigurationUpdateFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBConfigurationUpdateFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBConfigurationUpdateFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBConfigurationUpdateFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateFailureIEField{}
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
	var zero ENBConfigurationUpdateFailureIEValue

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

// MMEConfigurationUpdateAcknowledgeIEContainer is the concrete ProtocolIEContainer[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEContainer []MMEConfigurationUpdateAcknowledgeIEField

// MMEConfigurationUpdateAcknowledgeIEField is the concrete ProtocolIEField[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEConfigurationUpdateAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEField) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEConfigurationUpdateAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEConfigurationUpdateAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEConfigurationUpdateAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateAcknowledgeIEField{}
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
	var zero MMEConfigurationUpdateAcknowledgeIEValue

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

// CriticalityDiagnosticsValueCodec is the concrete ValueCodec[CriticalityDiagnostics].
type CriticalityDiagnosticsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnostics,

		error)
	encode func(CriticalityDiagnostics,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnostics, aper.DecodeState,

	) (CriticalityDiagnostics, aper.Snapshot,

	)
	compare func(CriticalityDiagnostics, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsValueCodec) New(value CriticalityDiagnostics,

) (CriticalityDiagnosticsAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsValueCodec) EncodeAPER(value CriticalityDiagnosticsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CriticalityDiagnosticsValueCodec) encodeBudgetValue(value CriticalityDiagnostics,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsValueCodec) encodeChanged(value CriticalityDiagnostics,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) ENBConfigurationUpdateAcknowledgeIEValue

	get func(*ENBConfigurationUpdateAcknowledgeIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (ENBConfigurationUpdateAcknowledgeIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *ENBConfigurationUpdateAcknowledgeIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateFailureCauseIEBinding is the concrete IEBinding[Cause, ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) ENBConfigurationUpdateFailureIEValue

	get func(*ENBConfigurationUpdateFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateFailureCauseIEBinding) New(value s14.Cause,

) (ENBConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Get(field *ENBConfigurationUpdateFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateFailureTimeToWaitIEBinding is the concrete IEBinding[TimeToWait, ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureTimeToWaitIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeToWaitValueCodec
	inject func(s00.TimeToWait,

	) ENBConfigurationUpdateFailureIEValue

	get func(*ENBConfigurationUpdateFailureIEValue,

	) (*s00.TimeToWait,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureTimeToWaitIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureTimeToWaitIEBinding) Codec() s02.TimeToWaitValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateFailureTimeToWaitIEBinding) New(value s00.TimeToWait,

) (ENBConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeToWaitValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateFailureTimeToWaitIEBinding) Get(field *ENBConfigurationUpdateFailureIEField) (*s00.TimeToWait,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) ENBConfigurationUpdateFailureIEValue

	get func(*ENBConfigurationUpdateFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (ENBConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) Get(field *ENBConfigurationUpdateFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCancelAcknowledgeMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverCancelAcknowledgeIEValue

	get func(*HandoverCancelAcknowledgeIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelAcknowledgeMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelAcknowledgeMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCancelAcknowledgeMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverCancelAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelAcknowledgeMMEUES1APIDIEBinding) Get(field *HandoverCancelAcknowledgeIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCancelAcknowledgeENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverCancelAcknowledgeIEValue

	get func(*HandoverCancelAcknowledgeIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelAcknowledgeENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelAcknowledgeENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCancelAcknowledgeENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverCancelAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelAcknowledgeENBUES1APIDIEBinding) Get(field *HandoverCancelAcknowledgeIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) HandoverCancelAcknowledgeIEValue

	get func(*HandoverCancelAcknowledgeIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (HandoverCancelAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *HandoverCancelAcknowledgeIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverFailureIEValue].
type HandoverFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverFailureIEValue

	get func(*HandoverFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverFailureIEField, error) {
	if b.inject == nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverFailureMMEUES1APIDIEBinding) Get(field *HandoverFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverFailureCauseIEBinding is the concrete IEBinding[Cause, HandoverFailureIEValue].
type HandoverFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) HandoverFailureIEValue

	get func(*HandoverFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverFailureCauseIEBinding) New(value s14.Cause,

) (HandoverFailureIEField, error) {
	if b.inject == nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverFailureCauseIEBinding) Get(field *HandoverFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, HandoverFailureIEValue].
type HandoverFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) HandoverFailureIEValue

	get func(*HandoverFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (HandoverFailureIEField, error) {
	if b.inject == nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverFailureCriticalityDiagnosticsIEBinding) Get(field *HandoverFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverPreparationFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverPreparationFailureIEValue].
type HandoverPreparationFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverPreparationFailureIEValue

	get func(*HandoverPreparationFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverPreparationFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverPreparationFailureIEField, error) {
	if b.inject == nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverPreparationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverPreparationFailureMMEUES1APIDIEBinding) Get(field *HandoverPreparationFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverPreparationFailureENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverPreparationFailureIEValue].
type HandoverPreparationFailureENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverPreparationFailureIEValue

	get func(*HandoverPreparationFailureIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverPreparationFailureENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverPreparationFailureIEField, error) {
	if b.inject == nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverPreparationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverPreparationFailureENBUES1APIDIEBinding) Get(field *HandoverPreparationFailureIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverPreparationFailureCauseIEBinding is the concrete IEBinding[Cause, HandoverPreparationFailureIEValue].
type HandoverPreparationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) HandoverPreparationFailureIEValue

	get func(*HandoverPreparationFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverPreparationFailureCauseIEBinding) New(value s14.Cause,

) (HandoverPreparationFailureIEField, error) {
	if b.inject == nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverPreparationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverPreparationFailureCauseIEBinding) Get(field *HandoverPreparationFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverPreparationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, HandoverPreparationFailureIEValue].
type HandoverPreparationFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) HandoverPreparationFailureIEValue

	get func(*HandoverPreparationFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverPreparationFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (HandoverPreparationFailureIEField, error) {
	if b.inject == nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverPreparationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverPreparationFailureCriticalityDiagnosticsIEBinding) Get(field *HandoverPreparationFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupFailureMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, InitialContextSetupFailureIEValue].
type InitialContextSetupFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) InitialContextSetupFailureIEValue

	get func(*InitialContextSetupFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (InitialContextSetupFailureIEField, error) {
	if b.inject == nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupFailureMMEUES1APIDIEBinding) Get(field *InitialContextSetupFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupFailureENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, InitialContextSetupFailureIEValue].
type InitialContextSetupFailureENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) InitialContextSetupFailureIEValue

	get func(*InitialContextSetupFailureIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupFailureENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (InitialContextSetupFailureIEField, error) {
	if b.inject == nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupFailureENBUES1APIDIEBinding) Get(field *InitialContextSetupFailureIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupFailureCauseIEBinding is the concrete IEBinding[Cause, InitialContextSetupFailureIEValue].
type InitialContextSetupFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) InitialContextSetupFailureIEValue

	get func(*InitialContextSetupFailureIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialContextSetupFailureCauseIEBinding) New(value s14.Cause,

) (InitialContextSetupFailureIEField, error) {
	if b.inject == nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupFailureCauseIEBinding) Get(field *InitialContextSetupFailureIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, InitialContextSetupFailureIEValue].
type InitialContextSetupFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) InitialContextSetupFailureIEValue

	get func(*InitialContextSetupFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (InitialContextSetupFailureIEField, error) {
	if b.inject == nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupFailureCriticalityDiagnosticsIEBinding) Get(field *InitialContextSetupFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) MMEConfigurationUpdateAcknowledgeIEValue

	get func(*MMEConfigurationUpdateAcknowledgeIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (MMEConfigurationUpdateAcknowledgeIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *MMEConfigurationUpdateAcknowledgeIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellActivationRequestValueCodec is the concrete ValueCodec[CellActivationRequest].
type CellActivationRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellActivationRequest,

		error)
	encode func(CellActivationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellActivationRequest, aper.DecodeState,

	) (CellActivationRequest, aper.Snapshot,

	)
	compare func(CellActivationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellActivationRequestValueCodec) New(value CellActivationRequest,

) (CellActivationRequestAPERValue, error) {
	if c.encode == nil {
		return CellActivationRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellActivationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellActivationRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellActivationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellActivationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellActivationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellActivationRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellActivationRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellActivationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellActivationRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellActivationRequestValueCodec) EncodeAPER(value CellActivationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellActivationRequestValueCodec) encodeBudgetValue(value CellActivationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellActivationRequestValueCodec) encodeChanged(value CellActivationRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedMDTValueCodec is the concrete ValueCodec[CellBasedMDT].
type CellBasedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedMDT,

		error)
	encode func(CellBasedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedMDT, aper.DecodeState,

	) (CellBasedMDT, aper.Snapshot,

	)
	compare func(CellBasedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedMDTValueCodec) New(value CellBasedMDT,

) (CellBasedMDTAPERValue, error) {
	if c.encode == nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedMDTValueCodec) EncodeAPER(value CellBasedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedMDTValueCodec) encodeBudgetValue(value CellBasedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedMDTValueCodec) encodeChanged(value CellBasedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedQMCValueCodec is the concrete ValueCodec[CellBasedQMC].
type CellBasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedQMC,

		error)
	encode func(CellBasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedQMC, aper.DecodeState,

	) (CellBasedQMC, aper.Snapshot,

	)
	compare func(CellBasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedQMCValueCodec) New(value CellBasedQMC,

) (CellBasedQMCAPERValue, error) {
	if c.encode == nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedQMCValueCodec) EncodeAPER(value CellBasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedQMCValueCodec) encodeBudgetValue(value CellBasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedQMCValueCodec) encodeChanged(value CellBasedQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDBroadcastValueCodec is the concrete ValueCodec[EmergencyAreaIDBroadcast].
type EmergencyAreaIDBroadcastValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcast,

		error)
	encode func(EmergencyAreaIDBroadcast,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDBroadcast, aper.DecodeState,

	) (EmergencyAreaIDBroadcast, aper.Snapshot,

	)
	compare func(EmergencyAreaIDBroadcast, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDBroadcastValueCodec) New(value EmergencyAreaIDBroadcast,

) (EmergencyAreaIDBroadcastAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDBroadcastAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDBroadcastAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDBroadcastAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDBroadcastAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDBroadcastValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDBroadcastAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDBroadcastAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDBroadcastAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDBroadcastAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDBroadcastAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDBroadcastValueCodec) EncodeAPER(value EmergencyAreaIDBroadcastAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDBroadcastValueCodec) encodeBudgetValue(value EmergencyAreaIDBroadcast,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDBroadcastValueCodec) encodeChanged(value EmergencyAreaIDBroadcast,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDBroadcastItemValueCodec is the concrete ValueCodec[EmergencyAreaIDBroadcastItem].
type EmergencyAreaIDBroadcastItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItem,

		error)
	encode func(EmergencyAreaIDBroadcastItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDBroadcastItem, aper.DecodeState,

	) (EmergencyAreaIDBroadcastItem, aper.Snapshot,

	)
	compare func(EmergencyAreaIDBroadcastItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDBroadcastItemValueCodec) New(value EmergencyAreaIDBroadcastItem,

) (EmergencyAreaIDBroadcastItemAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDBroadcastItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDBroadcastItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDBroadcastItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDBroadcastItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDBroadcastItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDBroadcastItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDBroadcastItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDBroadcastItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDBroadcastItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDBroadcastItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDBroadcastItemValueCodec) EncodeAPER(value EmergencyAreaIDBroadcastItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDBroadcastItemValueCodec) encodeBudgetValue(value EmergencyAreaIDBroadcastItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDBroadcastItemValueCodec) encodeChanged(value EmergencyAreaIDBroadcastItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelled].
type EmergencyAreaIDCancelledValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelled,

		error)
	encode func(EmergencyAreaIDCancelled,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelled, aper.DecodeState,

	) (EmergencyAreaIDCancelled, aper.Snapshot,

	)
	compare func(EmergencyAreaIDCancelled, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledValueCodec) New(value EmergencyAreaIDCancelled,

) (EmergencyAreaIDCancelledAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledValueCodec) EncodeAPER(value EmergencyAreaIDCancelledAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDCancelledValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelled,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledValueCodec) encodeChanged(value EmergencyAreaIDCancelled,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledItemValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelledItem].
type EmergencyAreaIDCancelledItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItem,

		error)
	encode func(EmergencyAreaIDCancelledItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelledItem, aper.DecodeState,

	) (EmergencyAreaIDCancelledItem, aper.Snapshot,

	)
	compare func(EmergencyAreaIDCancelledItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledItemValueCodec) New(value EmergencyAreaIDCancelledItem,

) (EmergencyAreaIDCancelledItemAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledItemValueCodec) EncodeAPER(value EmergencyAreaIDCancelledItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDCancelledItemValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelledItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledItemValueCodec) encodeChanged(value EmergencyAreaIDCancelledItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HOReportValueCodec is the concrete ValueCodec[HOReport].
type HOReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HOReport,

		error)
	encode func(HOReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HOReport, aper.DecodeState,

	) (HOReport, aper.Snapshot,

	)
	compare func(HOReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HOReportValueCodec) New(value HOReport,

) (HOReportAPERValue, error) {
	if c.encode == nil {
		return HOReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HOReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HOReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HOReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HOReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HOReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HOReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HOReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HOReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HOReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HOReportValueCodec) EncodeAPER(value HOReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HOReportValueCodec) encodeBudgetValue(value HOReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HOReportValueCodec) encodeChanged(value HOReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsAPERValue is the concrete APERValue[CriticalityDiagnostics].
type CriticalityDiagnosticsAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnostics

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsAPERValue) WithoutReplay() CriticalityDiagnosticsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellActivationRequestAPERValue is the concrete APERValue[CellActivationRequest].
type CellActivationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellActivationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellActivationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellActivationRequestAPERValue) WithoutReplay() CellActivationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedMDTAPERValue is the concrete APERValue[CellBasedMDT].
type CellBasedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellBasedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTAPERValue) WithoutReplay() CellBasedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedQMCAPERValue is the concrete APERValue[CellBasedQMC].
type CellBasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellBasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCAPERValue) WithoutReplay() CellBasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDBroadcastAPERValue is the concrete APERValue[EmergencyAreaIDBroadcast].
type EmergencyAreaIDBroadcastAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDBroadcast

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDBroadcastAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastAPERValue) WithoutReplay() EmergencyAreaIDBroadcastAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDBroadcastItemAPERValue is the concrete APERValue[EmergencyAreaIDBroadcastItem].
type EmergencyAreaIDBroadcastItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDBroadcastItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDBroadcastItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDBroadcastItemAPERValue) WithoutReplay() EmergencyAreaIDBroadcastItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledAPERValue is the concrete APERValue[EmergencyAreaIDCancelled].
type EmergencyAreaIDCancelledAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDCancelled

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledAPERValue) WithoutReplay() EmergencyAreaIDCancelledAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledItemAPERValue is the concrete APERValue[EmergencyAreaIDCancelledItem].
type EmergencyAreaIDCancelledItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDCancelledItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemAPERValue) WithoutReplay() EmergencyAreaIDCancelledItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HOReportAPERValue is the concrete APERValue[HOReport].
type HOReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   HOReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HOReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HOReportAPERValue) WithoutReplay() HOReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error)
	encode  func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) New(value ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList is the concrete ERABIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueERABIEContainerList, error)
	encode  func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) New(value ENBConfigurationUpdateFailureIEValueERABIEContainerList) (ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueERABIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueERABIEContainerList, error)
	encode  func(HandoverCancelAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) New(value HandoverCancelAcknowledgeIEValueERABIEContainerList) (HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverCancelAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelAcknowledgeIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueERABIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailureIEValueERABIEContainerList, error)
	encode  func(HandoverFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailureIEValueERABIEContainerList, aper.DecodeState) (HandoverFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureIEValueERABIEContainerListValueCodec) New(value HandoverFailureIEValueERABIEContainerList) (HandoverFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverFailureIEValue].
type HandoverFailureIEValueERABIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueERABIEContainerList, error)
	encode  func(HandoverPreparationFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailureIEValueERABIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureIEValueERABIEContainerListValueCodec) New(value HandoverPreparationFailureIEValueERABIEContainerList) (HandoverPreparationFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverPreparationFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverPreparationFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverPreparationFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverPreparationFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueERABIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueERABIEContainerList, error)
	encode  func(InitialContextSetupFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailureIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureIEValueERABIEContainerListValueCodec) New(value InitialContextSetupFailureIEValueERABIEContainerList) (InitialContextSetupFailureIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureIEValueERABIEContainerListValueCodec) EncodeAPER(value InitialContextSetupFailureIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupFailureIEValueERABIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureIEValueERABIEContainerListValueCodec) encodeChanged(value InitialContextSetupFailureIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureIEValueERABIEContainerList is the concrete ERABIEContainerList[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueERABIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error)
	encode  func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) New(value MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList is the concrete ERABIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEField, error)
	encode  func(ENBConfigurationUpdateAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledgeIEField, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) New(value ENBConfigurationUpdateAcknowledgeIEField) (ENBConfigurationUpdateAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEField, error)
	encode  func(ENBConfigurationUpdateFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailureIEField, aper.DecodeState) (ENBConfigurationUpdateFailureIEField, aper.Snapshot)
	compare func(ENBConfigurationUpdateFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureIEFieldValueCodec) New(value ENBConfigurationUpdateFailureIEField) (ENBConfigurationUpdateFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureIEFieldValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureIEFieldValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureIEFieldValueCodec) encodeChanged(value ENBConfigurationUpdateFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEField, error)
	encode  func(HandoverCancelAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledgeIEField, aper.DecodeState) (HandoverCancelAcknowledgeIEField, aper.Snapshot)
	compare func(HandoverCancelAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeIEFieldValueCodec) New(value HandoverCancelAcknowledgeIEField) (HandoverCancelAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeIEFieldValueCodec) EncodeAPER(value HandoverCancelAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCancelAcknowledgeIEFieldValueCodec) encodeBudgetValue(value HandoverCancelAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeIEFieldValueCodec) encodeChanged(value HandoverCancelAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverFailureIEValue]].
type HandoverFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailureIEField, error)
	encode  func(HandoverFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailureIEField, aper.DecodeState) (HandoverFailureIEField, aper.Snapshot)
	compare func(HandoverFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureIEFieldValueCodec) New(value HandoverFailureIEField) (HandoverFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureIEFieldValueCodec) EncodeAPER(value HandoverFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverFailureIEFieldValueCodec) encodeBudgetValue(value HandoverFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureIEFieldValueCodec) encodeChanged(value HandoverFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailureIEField, error)
	encode  func(HandoverPreparationFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailureIEField, aper.DecodeState) (HandoverPreparationFailureIEField, aper.Snapshot)
	compare func(HandoverPreparationFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureIEFieldValueCodec) New(value HandoverPreparationFailureIEField) (HandoverPreparationFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureIEFieldValueCodec) EncodeAPER(value HandoverPreparationFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverPreparationFailureIEFieldValueCodec) encodeBudgetValue(value HandoverPreparationFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureIEFieldValueCodec) encodeChanged(value HandoverPreparationFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailureIEField, error)
	encode  func(InitialContextSetupFailureIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailureIEField, aper.DecodeState) (InitialContextSetupFailureIEField, aper.Snapshot)
	compare func(InitialContextSetupFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureIEFieldValueCodec) New(value InitialContextSetupFailureIEField) (InitialContextSetupFailureIEFieldAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureIEFieldValueCodec) EncodeAPER(value InitialContextSetupFailureIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupFailureIEFieldValueCodec) encodeBudgetValue(value InitialContextSetupFailureIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureIEFieldValueCodec) encodeChanged(value InitialContextSetupFailureIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEField, error)
	encode  func(MMEConfigurationUpdateAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledgeIEField, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot)
	compare func(MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) New(value MMEConfigurationUpdateAcknowledgeIEField) (MMEConfigurationUpdateAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEContainer, error)
	encode  func(ENBConfigurationUpdateAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledgeIEContainer, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) New(value ENBConfigurationUpdateAcknowledgeIEContainer) (ENBConfigurationUpdateAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEContainer, error)
	encode  func(ENBConfigurationUpdateFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailureIEContainer, aper.DecodeState) (ENBConfigurationUpdateFailureIEContainer, aper.Snapshot)
	compare func(ENBConfigurationUpdateFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureIEContainerValueCodec) New(value ENBConfigurationUpdateFailureIEContainer) (ENBConfigurationUpdateFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureIEContainerValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureIEContainerValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureIEContainerValueCodec) encodeChanged(value ENBConfigurationUpdateFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEContainer, error)
	encode  func(HandoverCancelAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledgeIEContainer, aper.DecodeState) (HandoverCancelAcknowledgeIEContainer, aper.Snapshot)
	compare func(HandoverCancelAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeIEContainerValueCodec) New(value HandoverCancelAcknowledgeIEContainer) (HandoverCancelAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeIEContainerValueCodec) EncodeAPER(value HandoverCancelAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCancelAcknowledgeIEContainerValueCodec) encodeBudgetValue(value HandoverCancelAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeIEContainerValueCodec) encodeChanged(value HandoverCancelAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverFailureIEValue]].
type HandoverFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailureIEContainer, error)
	encode  func(HandoverFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailureIEContainer, aper.DecodeState) (HandoverFailureIEContainer, aper.Snapshot)
	compare func(HandoverFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureIEContainerValueCodec) New(value HandoverFailureIEContainer) (HandoverFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureIEContainerValueCodec) EncodeAPER(value HandoverFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverFailureIEContainerValueCodec) encodeBudgetValue(value HandoverFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureIEContainerValueCodec) encodeChanged(value HandoverFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailureIEContainer, error)
	encode  func(HandoverPreparationFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailureIEContainer, aper.DecodeState) (HandoverPreparationFailureIEContainer, aper.Snapshot)
	compare func(HandoverPreparationFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureIEContainerValueCodec) New(value HandoverPreparationFailureIEContainer) (HandoverPreparationFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureIEContainerValueCodec) EncodeAPER(value HandoverPreparationFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverPreparationFailureIEContainerValueCodec) encodeBudgetValue(value HandoverPreparationFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureIEContainerValueCodec) encodeChanged(value HandoverPreparationFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailureIEContainer, error)
	encode  func(InitialContextSetupFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailureIEContainer, aper.DecodeState) (InitialContextSetupFailureIEContainer, aper.Snapshot)
	compare func(InitialContextSetupFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureIEContainerValueCodec) New(value InitialContextSetupFailureIEContainer) (InitialContextSetupFailureIEContainerAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureIEContainerValueCodec) EncodeAPER(value InitialContextSetupFailureIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupFailureIEContainerValueCodec) encodeBudgetValue(value InitialContextSetupFailureIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureIEContainerValueCodec) encodeChanged(value InitialContextSetupFailureIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEContainer, error)
	encode  func(MMEConfigurationUpdateAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledgeIEContainer, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot)
	compare func(MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) New(value MMEConfigurationUpdateAcknowledgeIEContainer) (MMEConfigurationUpdateAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) New(value ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverFailureIEValueProtocolErrorIEContainerList) (HandoverFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverFailureIEValue].
type HandoverFailureIEValueProtocolErrorIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverPreparationFailureIEValueProtocolErrorIEContainerList) (HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverPreparationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverPreparationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueProtocolErrorIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolErrorIEContainerList, error)
	encode  func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) New(value InitialContextSetupFailureIEValueProtocolErrorIEContainerList) (InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value InitialContextSetupFailureIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueProtocolErrorIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, error)
	encode  func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) New(value ENBConfigurationUpdateFailureIEValueProtocolIEContainerList) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueProtocolIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value HandoverCancelAcknowledgeIEValueProtocolIEContainerList) (HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverCancelAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelAcknowledgeIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueProtocolIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverFailureIEValueProtocolIEContainerList, error)
	encode  func(HandoverFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverFailureIEValueProtocolIEContainerList, aper.DecodeState) (HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFailureIEValueProtocolIEContainerListValueCodec) New(value HandoverFailureIEValueProtocolIEContainerList) (HandoverFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverFailureIEValue].
type HandoverFailureIEValueProtocolIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolIEContainerList, error)
	encode  func(HandoverPreparationFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverPreparationFailureIEValueProtocolIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) New(value HandoverPreparationFailureIEValueProtocolIEContainerList) (HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverPreparationFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverPreparationFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverPreparationFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueProtocolIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolIEContainerList, error)
	encode  func(InitialContextSetupFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupFailureIEValueProtocolIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) New(value InitialContextSetupFailureIEValueProtocolIEContainerList) (InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value InitialContextSetupFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupFailureIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueProtocolIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer = ENBConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer = ENBConfigurationUpdateFailureIEField

// HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverCancelAcknowledgeIEValue].
type HandoverCancelAcknowledgeIEValueProtocolIESingleContainer = HandoverCancelAcknowledgeIEField

// HandoverFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverFailureIEValue].
type HandoverFailureIEValueProtocolIESingleContainer = HandoverFailureIEField

// HandoverPreparationFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverPreparationFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverPreparationFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverPreparationFailureIEValue].
type HandoverPreparationFailureIEValueProtocolIESingleContainer = HandoverPreparationFailureIEField

// InitialContextSetupFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupFailureIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEValueERABIEContainerListAPERValue) WithoutReplay() InitialContextSetupFailureIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[InitialContextSetupFailureIEValue].
type InitialContextSetupFailureIEValueProtocolIESingleContainer = InitialContextSetupFailureIEField

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MMEConfigurationUpdateAcknowledgeIEValue].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer = MMEConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateAcknowledgeIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEFieldAPERValue) WithoutReplay() ENBConfigurationUpdateFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEFieldAPERValue) WithoutReplay() HandoverCancelAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverFailureIEValue]].
type HandoverFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEFieldAPERValue) WithoutReplay() HandoverFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverPreparationFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEFieldAPERValue) WithoutReplay() HandoverPreparationFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureIEFieldAPERValue is the concrete APERValue[ProtocolIEField[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupFailureIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEFieldAPERValue) WithoutReplay() InitialContextSetupFailureIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeIEFieldAPERValue is the concrete APERValue[ProtocolIEField[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEContainerAPERValue) WithoutReplay() ENBConfigurationUpdateFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEContainerAPERValue) WithoutReplay() HandoverCancelAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverFailureIEValue]].
type HandoverFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEContainerAPERValue) WithoutReplay() HandoverFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverPreparationFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEContainerAPERValue) WithoutReplay() HandoverPreparationFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupFailureIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEContainerAPERValue) WithoutReplay() InitialContextSetupFailureIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverPreparationFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupFailureIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ENBConfigurationUpdateAcknowledgeIEValue]].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ENBConfigurationUpdateFailureIEValue]].
type ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverCancelAcknowledgeIEValue]].
type HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverFailureIEValue]].
type HandoverFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverPreparationFailureIEValue]].
type HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverPreparationFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[InitialContextSetupFailureIEValue]].
type InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupFailureIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) WithoutReplay() InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[MMEConfigurationUpdateAcknowledgeIEValue]].
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCompareS1APCancelledCellinTAI(v *s17.CancelledCellinTAI, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCancelledCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCandidateCellList(v *s18.CandidateCellList, s *aper.SemanticComparison) {
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
			s18.BridgeCompareS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCandidatePCIList(v *s14.CandidatePCIList, s *aper.SemanticComparison) {
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
			s14.BridgeCompareS1APCandidatePCI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCellActivationRequest(v *CellActivationRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellsToActivateList(&v.CellsToActivateList, s)
	{
		f := s.Begin()
		s.Bool(v.MinimumActivationTime == nil)
		if v.MinimumActivationTime != nil {
			s.Int(int64((*v.MinimumActivationTime)))
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellActivationRequest(v *CellActivationRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellsToActivateList(&v.CellsToActivateList, s)
	{
		f := s.Begin()
		s.Bool(v.MinimumActivationTime == nil)
		if v.MinimumActivationTime != nil {
			s.Int(int64((*v.MinimumActivationTime)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellBasedMDT(v *CellBasedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIdListforMDT(&v.CellIdListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellBasedMDT(v *CellBasedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellIdListforMDT(&v.CellIdListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellBasedQMC(v *CellBasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIdListforQMC(&v.CellIdListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellBasedQMC(v *CellBasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellIdListforQMC(&v.CellIdListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDBroadcast(v *s17.CellIDBroadcast, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCellIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellIDCancelled(v *s17.CellIDCancelled, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCellIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellIdListforMDT(v *s17.CellIdListforMDT, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellIdListforQMC(v *s17.CellIdListforQMC, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellsToActivateList(v *s14.CellsToActivateList, s *aper.SemanticComparison) {
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
			s14.BridgeCompareS1APCellsToActivateListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCompletedCellinEAI(v *s17.CompletedCellinEAI, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCompletedCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCompletedCellinTAI(v *s17.CompletedCellinTAI, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCompletedCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCriticalityDiagnostics(v *CriticalityDiagnostics, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ProcedureCode == nil)
		if v.ProcedureCode != nil {
			s00.BridgeCaptureS1APProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			s00.BridgeCaptureS1APTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			s00.BridgeCaptureS1APCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	s21.BridgeCaptureS1APCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnostics(v *CriticalityDiagnostics, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ProcedureCode == nil)
		if v.ProcedureCode != nil {
			s02.BridgeCompareS1APProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			s07.BridgeCompareS1APTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			s02.BridgeCompareS1APCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	BridgeCompareS1APCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnosticsIEList(v *s14.CriticalityDiagnosticsIEList, s *aper.SemanticComparison) {
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
			s14.BridgeCompareS1APCriticalityDiagnosticsIEItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APENBConfigurationUpdateAcknowledgeIEValue(v *ENBConfigurationUpdateAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) ENBConfigurationUpdateAcknowledgeIEValue {
	BridgeCaptureS1APENBConfigurationUpdateAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBConfigurationUpdateAcknowledgeIEValue(v *ENBConfigurationUpdateAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBConfigurationUpdateAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBConfigurationUpdateFailureIEValue(v *ENBConfigurationUpdateFailureIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateFailureIEValue) captureSemantics(s aper.SemanticCapture) ENBConfigurationUpdateFailureIEValue {
	BridgeCaptureS1APENBConfigurationUpdateFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBConfigurationUpdateFailureIEValue(v *ENBConfigurationUpdateFailureIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBConfigurationUpdateFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APEmergencyAreaIDBroadcast(v *EmergencyAreaIDBroadcast, s *aper.SemanticCapture) {
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
			BridgeCaptureS1APEmergencyAreaIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APEmergencyAreaIDBroadcastItem(v *EmergencyAreaIDBroadcastItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	s21.BridgeCaptureS1APCompletedCellinEAI(&v.CompletedCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDBroadcastItem(v *EmergencyAreaIDBroadcastItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	BridgeCompareS1APCompletedCellinEAI(&v.CompletedCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEmergencyAreaIDCancelled(v *EmergencyAreaIDCancelled, s *aper.SemanticCapture) {
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
			BridgeCaptureS1APEmergencyAreaIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APEmergencyAreaIDCancelledItem(v *EmergencyAreaIDCancelledItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	s21.BridgeCaptureS1APCancelledCellinEAI(&v.CancelledCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDCancelledItem(v *EmergencyAreaIDCancelledItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	s21.BridgeCompareS1APCancelledCellinEAI(&v.CancelledCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHOReport(v *HOReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APHoType(&v.HoType, s)
	s00.BridgeCaptureS1APHoReportType(&v.HoReportType, s)
	s18.BridgeCaptureS1APIRATCellID(&v.HosourceID, s)
	s18.BridgeCaptureS1APIRATCellID(&v.HoTargetID, s)
	s21.BridgeCaptureS1APCandidateCellList(&v.CandidateCellList, s)
	s.Bool(v.CandidatePCIList == nil)
	s21.BridgeCaptureS1APCandidatePCIList(&v.CandidatePCIList, s)
	s.ExtensionData(v.extData, v.extWire, 1)
	s.End(f, &v.replay, v.withoutReplay)
	if (v.CandidatePCIList != nil) && len(v.extWire) > 0 {
		s.CheckReceived(v.replay, v.extWire[0])
	}
}
func BridgeCompareS1APHOReport(v *HOReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APHoType(&v.HoType, s)
	s02.BridgeCompareS1APHoReportType(&v.HoReportType, s)
	s18.BridgeCompareS1APIRATCellID(&v.HosourceID, s)
	s18.BridgeCompareS1APIRATCellID(&v.HoTargetID, s)
	BridgeCompareS1APCandidateCellList(&v.CandidateCellList, s)
	s.Bool(v.CandidatePCIList == nil)
	BridgeCompareS1APCandidatePCIList(&v.CandidatePCIList, s)
	s.ExtensionData(v.extData, v.extWire, 1)
	s.End(f, v.replay, v.withoutReplay)
	if (v.CandidatePCIList != nil) && len(v.extWire) > 0 {
		s.CheckReceived(v.replay, v.extWire[0])
	}
}
func BridgeCaptureS1APHandoverCancelAcknowledgeIEValue(v *HandoverCancelAcknowledgeIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverCancelAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) HandoverCancelAcknowledgeIEValue {
	BridgeCaptureS1APHandoverCancelAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverCancelAcknowledgeIEValue(v *HandoverCancelAcknowledgeIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverCancelAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverCancelAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APHandoverFailureIEValue(v *HandoverFailureIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverFailureIEValue) captureSemantics(s aper.SemanticCapture) HandoverFailureIEValue {
	BridgeCaptureS1APHandoverFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverFailureIEValue(v *HandoverFailureIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APHandoverPreparationFailureIEValue(v *HandoverPreparationFailureIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverPreparationFailureIEValue) captureSemantics(s aper.SemanticCapture) HandoverPreparationFailureIEValue {
	BridgeCaptureS1APHandoverPreparationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverPreparationFailureIEValue(v *HandoverPreparationFailureIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverPreparationFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverPreparationFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APInitialContextSetupFailureIEValue(v *InitialContextSetupFailureIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialContextSetupFailureIEValue) captureSemantics(s aper.SemanticCapture) InitialContextSetupFailureIEValue {
	BridgeCaptureS1APInitialContextSetupFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APInitialContextSetupFailureIEValue(v *InitialContextSetupFailureIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialContextSetupFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APInitialContextSetupFailureIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEConfigurationUpdateAcknowledgeIEValue(v *MMEConfigurationUpdateAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) MMEConfigurationUpdateAcknowledgeIEValue {
	BridgeCaptureS1APMMEConfigurationUpdateAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEConfigurationUpdateAcknowledgeIEValue(v *MMEConfigurationUpdateAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEConfigurationUpdateAcknowledgeIEValue(&v, &s)
	return s
}

// CellBasedMDT represents the ASN.1 type CellBasedMDT (SEQUENCE).
type CellBasedMDT struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	CellIdListforMDT      s17.CellIdListforMDT               `asn1:"tag:0,context,implicit"`
	cellIdListforMDTIndef bool                               `asn1:"-" json:"-"`
	IEExtensions          s07.CellBasedMDTExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                               `asn1:"-" json:"-"`
	extCount              int64                              `asn1:"-" json:"-"`
	extPresent            []bool                             `asn1:"-" json:"-"`
	extData               [][]byte                           `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// CellBasedQMC represents the ASN.1 type CellBasedQMC (SEQUENCE).
type CellBasedQMC struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	CellIdListforQMC      s17.CellIdListforQMC               `asn1:"tag:0,context,implicit"`
	cellIdListforQMCIndef bool                               `asn1:"-" json:"-"`
	IEExtensions          s07.CellBasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                               `asn1:"-" json:"-"`
	extCount              int64                              `asn1:"-" json:"-"`
	extPresent            []bool                             `asn1:"-" json:"-"`
	extData               [][]byte                           `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// CriticalityDiagnostics represents the ASN.1 type CriticalityDiagnostics (SEQUENCE).
type CriticalityDiagnostics struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	received                       bool
	withoutReplay                  bool
	receivedAbsolute               bool
	receivedBytes                  aper.WireSpan
	receivedLocation               aper.Location
	ProcedureCode                  *s00.ProcedureCode                           `asn1:"tag:0,context,implicit,optional" json:"ProcedureCode,omitempty"`
	TriggeringMessage              *s00.TriggeringMessage                       `asn1:"tag:1,context,implicit,optional" json:"TriggeringMessage,omitempty"`
	ProcedureCriticality           *s00.Criticality                             `asn1:"tag:2,context,implicit,optional" json:"ProcedureCriticality,omitempty"`
	IEsCriticalityDiagnostics      s14.CriticalityDiagnosticsIEList             `asn1:"tag:3,context,implicit,optional" json:"IEsCriticalityDiagnostics,omitzero"`
	iEsCriticalityDiagnosticsIndef bool                                         `asn1:"-" json:"-"`
	IEExtensions                   s07.CriticalityDiagnosticsExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                         `asn1:"-" json:"-"`
	extCount                       int64                                        `asn1:"-" json:"-"`
	extPresent                     []bool                                       `asn1:"-" json:"-"`
	extData                        [][]byte                                     `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}
type EmergencyAreaIDBroadcast = []EmergencyAreaIDBroadcastItem

// EmergencyAreaIDBroadcastItem represents the ASN.1 type EmergencyAreaID-Broadcast-Item (SEQUENCE).
type EmergencyAreaIDBroadcastItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	EmergencyAreaID         s00.EmergencyAreaID                                `asn1:"tag:0,context,implicit"`
	CompletedCellinEAI      s17.CompletedCellinEAI                             `asn1:"tag:1,context,implicit"`
	completedCellinEAIIndef bool                                               `asn1:"-" json:"-"`
	IEExtensions            s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                               `asn1:"-" json:"-"`
	extCount                int64                                              `asn1:"-" json:"-"`
	extPresent              []bool                                             `asn1:"-" json:"-"`
	extData                 [][]byte                                           `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}
type EmergencyAreaIDCancelled = []EmergencyAreaIDCancelledItem

// EmergencyAreaIDCancelledItem represents the ASN.1 type EmergencyAreaID-Cancelled-Item (SEQUENCE).
type EmergencyAreaIDCancelledItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	EmergencyAreaID         s00.EmergencyAreaID                                `asn1:"tag:0,context,implicit"`
	CancelledCellinEAI      s17.CancelledCellinEAI                             `asn1:"tag:1,context,implicit"`
	cancelledCellinEAIIndef bool                                               `asn1:"-" json:"-"`
	IEExtensions            s09.EmergencyAreaIDCancelledItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                               `asn1:"-" json:"-"`
	extCount                int64                                              `asn1:"-" json:"-"`
	extPresent              []bool                                             `asn1:"-" json:"-"`
	extData                 [][]byte                                           `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// MarshalAPER encodes CellBasedMDT to APER format.
func (v *CellBasedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellBasedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CellIdListforMDT)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistformdt, fragmentLength_cellidlistformdt int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellidlistformdt < 0 || fragmentOffset_cellidlistformdt > int64(len(v.CellIdListforMDT)) || fragmentLength_cellidlistformdt < 0 || fragmentLength_cellidlistformdt > int64(len(v.CellIdListforMDT[fragmentOffset_cellidlistformdt:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellIdListforMDT[fragmentOffset_cellidlistformdt : fragmentOffset_cellidlistformdt+fragmentLength_cellidlistformdt] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellIdListforMDT element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellIdListforMDT: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCellBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes CellBasedMDT from APER format.
func (v *CellBasedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellBasedMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellBasedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellBasedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellBasedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedMDT{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellidlistformdt := bb.EnterComponent("CellIdListforMDT")
	v.CellIdListforMDT = make(s17.CellIdListforMDT, 0)
	_, errCollection_cellidlistformdt := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistformdt, fragmentLength_cellidlistformdt int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_cellidlistformdt < 0 || fragmentLength_cellidlistformdt < 0 || fragmentLength_cellidlistformdt > int64(^uint(0)>>1) || fragmentOffset_cellidlistformdt > int64(^uint(0)>>1)-fragmentLength_cellidlistformdt {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellidlistformdt; i++ {
			var elem s17.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_cellidlistformdt + i)
			if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdListforMDT[%d]", fragmentOffset_cellidlistformdt+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CellIdListforMDT, elem); err != nil {
				return err
			} else {
				v.CellIdListforMDT = next
			}
		}
		return nil
	})
	if errCollection_cellidlistformdt != nil {
		return runtime.WrapDecodePath(errCollection_cellidlistformdt, "CellIdListforMDT")
	}
	bb.LeaveComponent(toleranceMark_cellidlistformdt)
	if opt_ieextensions {
		tmp_ieextensions := make(s07.CellBasedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CellBasedMDTExtIEsExtField
				if err := s07.BridgeCellBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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

// MarshalAPER encodes CellBasedQMC to APER format.
func (v *CellBasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellBasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CellIdListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistforqmc, fragmentLength_cellidlistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellidlistforqmc < 0 || fragmentOffset_cellidlistforqmc > int64(len(v.CellIdListforQMC)) || fragmentLength_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc > int64(len(v.CellIdListforQMC[fragmentOffset_cellidlistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellIdListforQMC[fragmentOffset_cellidlistforqmc : fragmentOffset_cellidlistforqmc+fragmentLength_cellidlistforqmc] {
			if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellIdListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellIdListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCellBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes CellBasedQMC from APER format.
func (v *CellBasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellBasedQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellBasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellBasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellBasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedQMC{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellidlistforqmc := bb.EnterComponent("CellIdListforQMC")
	v.CellIdListforQMC = make(s17.CellIdListforQMC, 0)
	_, errCollection_cellidlistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistforqmc, fragmentLength_cellidlistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc > int64(^uint(0)>>1) || fragmentOffset_cellidlistforqmc > int64(^uint(0)>>1)-fragmentLength_cellidlistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellidlistforqmc; i++ {
			var elem s17.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_cellidlistforqmc + i)
			if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdListforQMC[%d]", fragmentOffset_cellidlistforqmc+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CellIdListforQMC, elem); err != nil {
				return err
			} else {
				v.CellIdListforQMC = next
			}
		}
		return nil
	})
	if errCollection_cellidlistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_cellidlistforqmc, "CellIdListforQMC")
	}
	bb.LeaveComponent(toleranceMark_cellidlistforqmc)
	if opt_ieextensions {
		tmp_ieextensions := make(s07.CellBasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CellBasedQMCExtIEsExtField
				if err := s07.BridgeCellBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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

// MarshalAPER encodes CriticalityDiagnostics to APER format.
func (v *CriticalityDiagnostics) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnostics) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.ProcedureCode != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TriggeringMessage != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ProcedureCriticality != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEsCriticalityDiagnostics != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ProcedureCode != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ProcedureCode), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
			return fmt.Errorf("encoding procedureCode: %w", err)
		}
	}
	if v.TriggeringMessage != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.TriggeringMessage), 3, false); err != nil {
			return fmt.Errorf("encoding triggeringMessage: %w", err)
		}
	}
	if v.ProcedureCriticality != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.ProcedureCriticality), 3, false); err != nil {
			return fmt.Errorf("encoding procedureCriticality: %w", err)
		}
	}
	if v.IEsCriticalityDiagnostics != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEsCriticalityDiagnostics)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentOffset_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics)) || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics : fragmentOffset_iescriticalitydiagnostics+fragmentLength_iescriticalitydiagnostics] {
				if err := s14.BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iEsCriticalityDiagnostics element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iEsCriticalityDiagnostics: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes CriticalityDiagnostics from APER format.
func (v *CriticalityDiagnostics) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnostics with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnostics) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnostics")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CriticalityDiagnostics) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnostics{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_procedurecode, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_triggeringmessage, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_procedurecriticality, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_iescriticalitydiagnostics, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_procedurecode {
		val_procedurecode, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ProcedureCode")
		}
		tmp_procedurecode := s00.ProcedureCode(val_procedurecode)
		if err := aper.ChargeValue(bb, tmp_procedurecode); err != nil {
			return err
		}
		v.ProcedureCode = (*s00.ProcedureCode)(bb.OwnInt64(int64(tmp_procedurecode)))

	}
	if opt_triggeringmessage {
		val_triggeringmessage, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "TriggeringMessage"})
		if err != nil {
			return runtime.WrapDecodePath(err, "TriggeringMessage")
		}
		tmp_triggeringmessage := s00.TriggeringMessage(val_triggeringmessage)
		if err := aper.ChargeValue(bb, tmp_triggeringmessage); err != nil {
			return err
		}
		v.TriggeringMessage = (*s00.TriggeringMessage)(bb.OwnInt64(int64(tmp_triggeringmessage)))

	}
	if opt_procedurecriticality {
		val_procedurecriticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "ProcedureCriticality"})
		if err != nil {
			return runtime.WrapDecodePath(err, "ProcedureCriticality")
		}
		tmp_procedurecriticality := s00.Criticality(val_procedurecriticality)
		if err := aper.ChargeValue(bb, tmp_procedurecriticality); err != nil {
			return err
		}
		v.ProcedureCriticality = (*s00.Criticality)(bb.OwnInt64(int64(tmp_procedurecriticality)))

	}
	if opt_iescriticalitydiagnostics {
		toleranceMark_iescriticalitydiagnostics := bb.EnterComponent("IEsCriticalityDiagnostics")
		tmp_iescriticalitydiagnostics := make(s14.CriticalityDiagnosticsIEList, 0)
		_, errCollection_iescriticalitydiagnostics := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(^uint(0)>>1) || fragmentOffset_iescriticalitydiagnostics > int64(^uint(0)>>1)-fragmentLength_iescriticalitydiagnostics {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_iescriticalitydiagnostics; i++ {
				var elem s14.CriticalityDiagnosticsIEItem
				elementMark := bb.EnterIndex(fragmentOffset_iescriticalitydiagnostics + i)
				if err := s14.BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEsCriticalityDiagnostics[%d]", fragmentOffset_iescriticalitydiagnostics+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_iescriticalitydiagnostics, elem); err != nil {
					return err
				} else {
					tmp_iescriticalitydiagnostics = next
				}
			}
			return nil
		})
		if errCollection_iescriticalitydiagnostics != nil {
			return runtime.WrapDecodePath(errCollection_iescriticalitydiagnostics, "IEsCriticalityDiagnostics")
		}
		v.IEsCriticalityDiagnostics = tmp_iescriticalitydiagnostics
		bb.LeaveComponent(toleranceMark_iescriticalitydiagnostics)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s07.CriticalityDiagnosticsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.CriticalityDiagnosticsExtIEsExtField
				if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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

type BridgeAsn1cAPEREmergencyAreaIDBroadcastListValue struct{ Value EmergencyAreaIDBroadcast }

// MarshalAPER encodes EmergencyAreaIDBroadcastItem to APER format.
func (v *EmergencyAreaIDBroadcastItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.EmergencyAreaID), 3, 3, true); err != nil {
		return fmt.Errorf("encoding emergencyAreaID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CompletedCellinEAI)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_completedcellineai, fragmentLength_completedcellineai int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_completedcellineai < 0 || fragmentOffset_completedcellineai > int64(len(v.CompletedCellinEAI)) || fragmentLength_completedcellineai < 0 || fragmentLength_completedcellineai > int64(len(v.CompletedCellinEAI[fragmentOffset_completedcellineai:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CompletedCellinEAI[fragmentOffset_completedcellineai : fragmentOffset_completedcellineai+fragmentLength_completedcellineai] {
			if err := s17.BridgeCompletedCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding completedCellinEAI element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding completedCellinEAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes EmergencyAreaIDBroadcastItem from APER format.
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDBroadcastItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDBroadcastItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDBroadcastItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_emergencyareaid, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaID")
	}
	v.EmergencyAreaID = s00.EmergencyAreaID(val_emergencyareaid)
	toleranceMark_completedcellineai := bb.EnterComponent("CompletedCellinEAI")
	v.CompletedCellinEAI = make(s17.CompletedCellinEAI, 0)
	_, errCollection_completedcellineai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_completedcellineai, fragmentLength_completedcellineai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_completedcellineai < 0 || fragmentLength_completedcellineai < 0 || fragmentLength_completedcellineai > int64(^uint(0)>>1) || fragmentOffset_completedcellineai > int64(^uint(0)>>1)-fragmentLength_completedcellineai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_completedcellineai; i++ {
			var elem s17.CompletedCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_completedcellineai + i)
			if err := s17.BridgeCompletedCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinEAI[%d]", fragmentOffset_completedcellineai+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CompletedCellinEAI, elem); err != nil {
				return err
			} else {
				v.CompletedCellinEAI = next
			}
		}
		return nil
	})
	if errCollection_completedcellineai != nil {
		return runtime.WrapDecodePath(errCollection_completedcellineai, "CompletedCellinEAI")
	}
	bb.LeaveComponent(toleranceMark_completedcellineai)
	if opt_ieextensions {
		tmp_ieextensions := make(s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.EmergencyAreaIDBroadcastItemExtIEsExtField
				if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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

type BridgeAsn1cAPEREmergencyAreaIDCancelledListValue struct{ Value EmergencyAreaIDCancelled }

// MarshalAPER encodes EmergencyAreaIDCancelledItem to APER format.
func (v *EmergencyAreaIDCancelledItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.EmergencyAreaID), 3, 3, true); err != nil {
		return fmt.Errorf("encoding emergencyAreaID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CancelledCellinEAI)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellineai, fragmentLength_cancelledcellineai int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cancelledcellineai < 0 || fragmentOffset_cancelledcellineai > int64(len(v.CancelledCellinEAI)) || fragmentLength_cancelledcellineai < 0 || fragmentLength_cancelledcellineai > int64(len(v.CancelledCellinEAI[fragmentOffset_cancelledcellineai:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CancelledCellinEAI[fragmentOffset_cancelledcellineai : fragmentOffset_cancelledcellineai+fragmentLength_cancelledcellineai] {
			if err := s17.BridgeCancelledCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cancelledCellinEAI element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cancelledCellinEAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes EmergencyAreaIDCancelledItem from APER format.
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDCancelledItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDCancelledItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDCancelledItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_emergencyareaid, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaID")
	}
	v.EmergencyAreaID = s00.EmergencyAreaID(val_emergencyareaid)
	toleranceMark_cancelledcellineai := bb.EnterComponent("CancelledCellinEAI")
	v.CancelledCellinEAI = make(s17.CancelledCellinEAI, 0)
	_, errCollection_cancelledcellineai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellineai, fragmentLength_cancelledcellineai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_cancelledcellineai < 0 || fragmentLength_cancelledcellineai < 0 || fragmentLength_cancelledcellineai > int64(^uint(0)>>1) || fragmentOffset_cancelledcellineai > int64(^uint(0)>>1)-fragmentLength_cancelledcellineai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cancelledcellineai; i++ {
			var elem s17.CancelledCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_cancelledcellineai + i)
			if err := s17.BridgeCancelledCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinEAI[%d]", fragmentOffset_cancelledcellineai+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CancelledCellinEAI, elem); err != nil {
				return err
			} else {
				v.CancelledCellinEAI = next
			}
		}
		return nil
	})
	if errCollection_cancelledcellineai != nil {
		return runtime.WrapDecodePath(errCollection_cancelledcellineai, "CancelledCellinEAI")
	}
	bb.LeaveComponent(toleranceMark_cancelledcellineai)
	if opt_ieextensions {
		tmp_ieextensions := make(s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.EmergencyAreaIDCancelledItemExtIEsExtField
				if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellBasedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellBasedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellBasedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellBasedMDT) WithoutReplay() CellBasedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellBasedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellBasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellBasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellBasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellBasedQMC) WithoutReplay() CellBasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellBasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnostics) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnostics", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CriticalityDiagnostics", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnostics) WithoutReplay() CriticalityDiagnostics {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CriticalityDiagnostics
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDBroadcastItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDBroadcastItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDBroadcastItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDBroadcastItem) WithoutReplay() EmergencyAreaIDBroadcastItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDBroadcastItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDCancelledItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDCancelledItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDCancelledItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDCancelledItem) WithoutReplay() EmergencyAreaIDCancelledItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDCancelledItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellBasedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellBasedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellBasedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellBasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellBasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellBasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnostics) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnostics) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnostics) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EmergencyAreaIDBroadcastItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EmergencyAreaIDBroadcastItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EmergencyAreaIDBroadcastItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EmergencyAreaIDCancelledItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EmergencyAreaIDCancelledItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EmergencyAreaIDCancelledItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellBasedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellBasedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellBasedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellBasedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellBasedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellBasedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellBasedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellBasedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellBasedMDT")
}
func (v *CellBasedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellBasedMDT")
}
func (v *CellBasedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellBasedMDT(v, &s)
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
func (v *CellBasedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellBasedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellBasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellBasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellBasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellBasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellBasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellBasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellBasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellBasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellBasedQMC")
}
func (v *CellBasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellBasedQMC")
}
func (v *CellBasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellBasedQMC(v, &s)
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
func (v *CellBasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellBasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CriticalityDiagnostics) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnostics")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CriticalityDiagnostics) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnostics")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCriticalityDiagnostics(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CriticalityDiagnostics")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CriticalityDiagnostics")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CriticalityDiagnostics) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CriticalityDiagnostics")
}
func (v *CriticalityDiagnostics) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CriticalityDiagnostics")
}
func (v *CriticalityDiagnostics) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCriticalityDiagnostics(v, &s)
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
func (v *CriticalityDiagnostics) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CriticalityDiagnostics) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EmergencyAreaIDBroadcastItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDBroadcastItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDBroadcastItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDBroadcastItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDBroadcastItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDBroadcastItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDBroadcastItem")
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDBroadcastItem")
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDBroadcastItem(v, &s)
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
func (v *EmergencyAreaIDBroadcastItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDBroadcastItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EmergencyAreaIDCancelledItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDCancelledItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDCancelledItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDCancelledItem(v, &s)
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
func (v *EmergencyAreaIDCancelledItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellBasedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellBasedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellBasedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellBasedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellBasedMDT{}
		return report, aper.OperationError(err, "CellBasedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellBasedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellBasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellBasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellBasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellBasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellBasedQMC{}
		return report, aper.OperationError(err, "CellBasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellBasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CriticalityDiagnostics) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnostics")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CriticalityDiagnostics
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCriticalityDiagnostics(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CriticalityDiagnostics{}
		return report, aper.OperationError(err, "CriticalityDiagnostics")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnostics")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDBroadcastItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDBroadcastItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDBroadcastItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDBroadcastItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDBroadcastItem{}
		return report, aper.OperationError(err, "EmergencyAreaIDBroadcastItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDBroadcastItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDCancelledItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDCancelledItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDCancelledItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDCancelledItem{}
		return report, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDCancelledItem")
}

// HOReport represents the ASN.1 type HOReport (SEQUENCE).
type HOReport struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	HoType                 s00.HoType             `asn1:"tag:0,context,implicit"`
	HoReportType           s00.HoReportType       `asn1:"tag:1,context,implicit"`
	HosourceID             s18.IRATCellID         `asn1:"tag:2,context,explicit"`
	HoTargetID             s18.IRATCellID         `asn1:"tag:3,context,explicit"`
	CandidateCellList      s18.CandidateCellList  `asn1:"tag:4,context,implicit"`
	candidateCellListIndef bool                   `asn1:"-" json:"-"`
	CandidatePCIList       s14.CandidatePCIList   `asn1:"tag:5,context,implicit,optional" json:"CandidatePCIList,omitzero"`
	candidatePCIListIndef  bool                   `asn1:"-" json:"-"`
	extCount               int64                  `asn1:"-" json:"-"`
	extPresent             []bool                 `asn1:"-" json:"-"`
	extData                [][]byte               `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// CellActivationRequest represents the ASN.1 type CellActivationRequest (SEQUENCE).
type CellActivationRequest struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	CellsToActivateList      s14.CellsToActivateList `asn1:"tag:0,context,implicit"`
	cellsToActivateListIndef bool                    `asn1:"-" json:"-"`
	MinimumActivationTime    *int64                  `asn1:"tag:1,context,implicit,optional" json:"MinimumActivationTime,omitempty"`
	extCount                 int64                   `asn1:"-" json:"-"`
	extPresent               []bool                  `asn1:"-" json:"-"`
	extData                  [][]byte                `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding       `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding  `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// MarshalAPER encodes HOReport to APER format.
func (v *HOReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HOReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	hasExtensions = hasExtensions || (v.CandidatePCIList != nil)
	for i, present := range v.extPresent {
		if i >= 1 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 1 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.HoType), 2, true); err != nil {
		return fmt.Errorf("encoding hoType: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.HoReportType), 1, true); err != nil {
		return fmt.Errorf("encoding hoReportType: %w", err)
	}
	if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&v.HosourceID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding hosourceID: %w", err)
	}
	if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&v.HoTargetID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding hoTargetID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CandidateCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_candidatecelllist < 0 || fragmentOffset_candidatecelllist > int64(len(v.CandidateCellList)) || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(len(v.CandidateCellList[fragmentOffset_candidatecelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CandidateCellList[fragmentOffset_candidatecelllist : fragmentOffset_candidatecelllist+fragmentLength_candidatecelllist] {
			if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding candidateCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding candidateCellList: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.CandidatePCIList != nil {
			extHighest = 0
		}
		if extensionCount > extHighest {
			extHighest = extensionCount
		}
		for i, present := range v.extPresent {
			if present && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		for i, data := range extensionEncodingData {
			if data != nil && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extHighest+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extHighest < 16383; gen/codegen_aper.go:353
		if extHighest < 0 || extHighest >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extHighest)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extHighest+1); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := v.CandidatePCIList != nil
			if err := aper.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_1: 0 <= extHighest < max int; gen/codegen_aper.go:369
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if v.CandidatePCIList != nil {
			extBuf := aper.NewBudgetBuffer(bb.Budget())
			if v.CandidatePCIList != nil {
				if err := aper.EncodeCollection(extBuf, int64(len(v.CandidatePCIList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
					if fragmentOffset_candidatepcilist < 0 || fragmentOffset_candidatepcilist > int64(len(v.CandidatePCIList)) || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(len(v.CandidatePCIList[fragmentOffset_candidatepcilist:])) {
						return fmt.Errorf("collection fragment outside value")
					}
					for _, elem := range v.CandidatePCIList[fragmentOffset_candidatepcilist : fragmentOffset_candidatepcilist+fragmentLength_candidatepcilist] {
						if err := s14.BridgeCandidatePCIMethodMarshalAPERTo(&elem, extBuf, len(fresh) != 0 && fresh[0]); err != nil {
							return fmt.Errorf("encoding candidatePCIList element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding candidatePCIList: %w", err)
				}
			}
			var extPadding aper.CompletePadding
			if !(len(fresh) != 0 && fresh[0]) && len(v.perExtPadding) > 0 {
				extPadding = v.perExtPadding[0]
			}
			extBytes, err := extBuf.CompleteBytesWithPadding(extPadding)
			if err != nil {
				return err
			}
			if err := aper.EncodeOpenTypeAligned(bb, extBytes); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_2: 0 <= extHighest < max int; gen/codegen_aper.go:421
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
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

// UnmarshalAPER decodes HOReport from APER format.
func (v *HOReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HOReport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HOReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "HOReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HOReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HOReport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_hotype, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "HoType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "HoType")
	}
	v.HoType = s00.HoType(val_hotype)
	val_horeporttype, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "HoReportType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "HoReportType")
	}
	v.HoReportType = s00.HoReportType(val_horeporttype)
	if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&v.HosourceID, bb); err != nil {
		return runtime.WrapDecodePath(err, "HosourceID")
	}
	if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&v.HoTargetID, bb); err != nil {
		return runtime.WrapDecodePath(err, "HoTargetID")
	}
	v.CandidateCellList = make(s18.CandidateCellList, 0)
	_, errCollection_candidatecelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_candidatecelllist < 0 || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(^uint(0)>>1) || fragmentOffset_candidatecelllist > int64(^uint(0)>>1)-fragmentLength_candidatecelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_candidatecelllist; i++ {
			var elem s18.IRATCellID
			if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CandidateCellList[%d]", fragmentOffset_candidatecelllist+i))
			}
			if next, err := aper.AppendValues(bb, v.CandidateCellList, elem); err != nil {
				return err
			} else {
				v.CandidateCellList = next
			}
		}
		return nil
	})
	if errCollection_candidatecelllist != nil {
		return runtime.WrapDecodePath(errCollection_candidatecelllist, "CandidateCellList")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_ALLOC_1: 0 <= extCount < max int; gen/codegen_aper.go:548
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_2: 0 <= extCount < max int; gen/codegen_aper.go:550
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[aper.CompletePadding](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.perExtPadding = make([]aper.CompletePadding, len(extPresent))
		if int64(0) <= extCount && extPresent[0] && extAdditions.Received(bb, 0) {
			extRaw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§19.9"})
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			extRaw.RetainContents(&v.extWire[0])
			if extAdditions.RecoveryEnabled(bb) {
				candidate := *v
				extBB := extRaw.ChildDecodeBuffer()
				if err := extBB.EnterOpenType(); err != nil {
					return err
				}
				checkpoint := extBB.CheckpointKnownAddition()
				decodeErr := func() error {
					v := &candidate
					_ = v
					recoveryMark_candidatepcilist := extBB.RecoveryComponent("CandidatePCIList")
					tmp_candidatepcilist := make(s14.CandidatePCIList, 0)
					_, errCollection_candidatepcilist := aper.DecodeCollection(extBB, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
						// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
						if fragmentOffset_candidatepcilist < 0 || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(^uint(0)>>1) || fragmentOffset_candidatepcilist > int64(^uint(0)>>1)-fragmentLength_candidatepcilist {
							return fmt.Errorf("collection fragment count out of range")
						}
						for i := int64(0); i < fragmentLength_candidatepcilist; i++ {
							var elem s14.CandidatePCI
							elementMark := extBB.RecoveryIndex(fragmentOffset_candidatepcilist + i)
							if err := s14.BridgeCandidatePCIMethodUnmarshalAPERFrom(&elem, extBB); err != nil {
								return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCIList[%d]", fragmentOffset_candidatepcilist+i))
							}
							extBB.LeaveComponent(elementMark)
							if next, err := aper.AppendValues(extBB, tmp_candidatepcilist, elem); err != nil {
								return err
							} else {
								tmp_candidatepcilist = next
							}
						}
						return nil
					})
					if errCollection_candidatepcilist != nil {
						return runtime.WrapDecodePath(errCollection_candidatepcilist, "CandidatePCIList")
					}
					v.CandidatePCIList = tmp_candidatepcilist
					extBB.LeaveComponent(recoveryMark_candidatepcilist)
					return nil
				}()
				decoded, padding, err := extAdditions.CompleteKnownOpenAddition(extBB, 0, extRaw, checkpoint, decodeErr)
				if err != nil {
					return err
				}
				if decoded {
					*v = candidate
					v.perExtPadding[0] = padding
				}
			} else {
				if err := func() error {
					extBB := extRaw.ChildDecodeBuffer()
					if err := extBB.EnterOpenType(); err != nil {
						return err
					}
					defer extBB.LeaveOpenType()
					_ = extBB
					recoveryMark_candidatepcilist := extBB.RecoveryComponent("CandidatePCIList")
					tmp_candidatepcilist := make(s14.CandidatePCIList, 0)
					_, errCollection_candidatepcilist := aper.DecodeCollection(extBB, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
						// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
						if fragmentOffset_candidatepcilist < 0 || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(^uint(0)>>1) || fragmentOffset_candidatepcilist > int64(^uint(0)>>1)-fragmentLength_candidatepcilist {
							return fmt.Errorf("collection fragment count out of range")
						}
						for i := int64(0); i < fragmentLength_candidatepcilist; i++ {
							var elem s14.CandidatePCI
							elementMark := extBB.RecoveryIndex(fragmentOffset_candidatepcilist + i)
							if err := s14.BridgeCandidatePCIMethodUnmarshalAPERFrom(&elem, extBB); err != nil {
								return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCIList[%d]", fragmentOffset_candidatepcilist+i))
							}
							extBB.LeaveComponent(elementMark)
							if next, err := aper.AppendValues(extBB, tmp_candidatepcilist, elem); err != nil {
								return err
							} else {
								tmp_candidatepcilist = next
							}
						}
						return nil
					})
					if errCollection_candidatepcilist != nil {
						return runtime.WrapDecodePath(errCollection_candidatepcilist, "CandidatePCIList")
					}
					v.CandidatePCIList = tmp_candidatepcilist
					extBB.LeaveComponent(recoveryMark_candidatepcilist)
					padding, err := aper.CaptureOpenTypePadding(extBB)
					if err != nil {
						return runtime.WrapDecodePath(err, "ExtData_[0]")
					}
					v.perExtPadding[0] = padding
					return nil
				}(); err != nil {
					return err
				}
			}
		}
		// arithmetic pattern APER_EXT_COUNT_LOOP_1: 0 <= extCount < max int; gen/codegen_aper.go:606
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
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

// MarshalAPER encodes CellActivationRequest to APER format.
func (v *CellActivationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellActivationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.MinimumActivationTime != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CellsToActivateList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellstoactivatelist < 0 || fragmentOffset_cellstoactivatelist > int64(len(v.CellsToActivateList)) || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(len(v.CellsToActivateList[fragmentOffset_cellstoactivatelist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellsToActivateList[fragmentOffset_cellstoactivatelist : fragmentOffset_cellstoactivatelist+fragmentLength_cellstoactivatelist] {
			if err := s14.BridgeCellsToActivateListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellsToActivateList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellsToActivateList: %w", err)
	}
	if v.MinimumActivationTime != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MinimumActivationTime), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(60), false); err != nil {
			return fmt.Errorf("encoding minimumActivationTime: %w", err)
		}
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

// UnmarshalAPER decodes CellActivationRequest from APER format.
func (v *CellActivationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellActivationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellActivationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellActivationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellActivationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellActivationRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_minimumactivationtime, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellstoactivatelist := bb.EnterComponent("CellsToActivateList")
	v.CellsToActivateList = make(s14.CellsToActivateList, 0)
	_, errCollection_cellstoactivatelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(^uint(0)>>1) || fragmentOffset_cellstoactivatelist > int64(^uint(0)>>1)-fragmentLength_cellstoactivatelist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellstoactivatelist; i++ {
			var elem s14.CellsToActivateListItem
			elementMark := bb.EnterIndex(fragmentOffset_cellstoactivatelist + i)
			if err := s14.BridgeCellsToActivateListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateList[%d]", fragmentOffset_cellstoactivatelist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CellsToActivateList, elem); err != nil {
				return err
			} else {
				v.CellsToActivateList = next
			}
		}
		return nil
	})
	if errCollection_cellstoactivatelist != nil {
		return runtime.WrapDecodePath(errCollection_cellstoactivatelist, "CellsToActivateList")
	}
	bb.LeaveComponent(toleranceMark_cellstoactivatelist)
	if opt_minimumactivationtime {
		val_minimumactivationtime, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(60), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MinimumActivationTime")
		}
		if err := aper.ChargeValue(bb, val_minimumactivationtime); err != nil {
			return err
		}
		v.MinimumActivationTime = (*int64)(bb.OwnInt64(int64(val_minimumactivationtime)))

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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellActivationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellActivationRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellActivationRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellActivationRequest) WithoutReplay() CellActivationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellActivationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HOReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HOReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HOReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HOReport) WithoutReplay() HOReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HOReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellActivationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellActivationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellActivationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HOReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	for len(views) > 0 && views[0].Index() < 1 {
		views = views[1:]
	}
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HOReport) SetExtension(index uint64, contents []byte) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HOReport) RemoveExtension(index uint64) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellActivationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellActivationRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellActivationRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellActivationRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellActivationRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellActivationRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellActivationRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellActivationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellActivationRequest")
}
func (v *CellActivationRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellActivationRequest")
}
func (v *CellActivationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellActivationRequest(v, &s)
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
func (v *CellActivationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellActivationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HOReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HOReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HOReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HOReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHOReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HOReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HOReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HOReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HOReport")
}
func (v *HOReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HOReport")
}
func (v *HOReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHOReport(v, &s)
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
func (v *HOReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HOReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellActivationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellActivationRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellActivationRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellActivationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellActivationRequest{}
		return report, aper.OperationError(err, "CellActivationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellActivationRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HOReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HOReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HOReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHOReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HOReport{}
		return report, aper.OperationError(err, "HOReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HOReport")
}

type ENBConfigurationUpdateAcknowledgeIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v ENBConfigurationUpdateAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBConfigurationUpdateAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *ENBConfigurationUpdateAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBConfigurationUpdateAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateAcknowledgeIEs"}}
}
func (ENBConfigurationUpdateAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ENBConfigurationUpdateAcknowledgeIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateAcknowledgeIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ENBConfigurationUpdateAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBConfigurationUpdateAcknowledgeIEValue, error) {
	out := ENBConfigurationUpdateAcknowledgeIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v ENBConfigurationUpdateAcknowledgeIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ENBConfigurationUpdateAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBConfigurationUpdateAcknowledgeIEValue:", v.id)
	}
}

type ENBConfigurationUpdateFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s14.Cause
	rowTimeToWait             *s00.TimeToWait
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v ENBConfigurationUpdateFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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

// Opaque returns the retained opaque open value of ENBConfigurationUpdateFailureIEValue and reports whether the opaque alternative is selected.
func (v *ENBConfigurationUpdateFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBConfigurationUpdateFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateFailureIEs"}}
}
func (ENBConfigurationUpdateFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
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

// AsCause returns the selected Cause value of ENBConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsTimeToWait returns the selected TimeToWait value of ENBConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateFailureIEValue) AsTimeToWait() (*s00.TimeToWait, bool) {
	if v == nil || v.id != s00.ProtocolIEID(65) || v.rowTimeToWait == nil {
		return nil, false
	}
	return v.rowTimeToWait, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ENBConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ENBConfigurationUpdateFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBConfigurationUpdateFailureIEValue, error) {
	out := ENBConfigurationUpdateFailureIEValue{id: id}
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
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v ENBConfigurationUpdateFailureIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ENBConfigurationUpdateFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateFailureIEs.id-Cause:")
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
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateFailureIEs.id-TimeToWait:")
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
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBConfigurationUpdateFailureIEValue:", v.id)
	}
}

type HandoverCancelAcknowledgeIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v HandoverCancelAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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

// Opaque returns the retained opaque open value of HandoverCancelAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *HandoverCancelAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverCancelAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelAcknowledgeIEs"}}
}
func (HandoverCancelAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverCancelAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverCancelAcknowledgeIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverCancelAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverCancelAcknowledgeIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of HandoverCancelAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverCancelAcknowledgeIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v HandoverCancelAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverCancelAcknowledgeIEValue, error) {
	out := HandoverCancelAcknowledgeIEValue{id: id}
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
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v HandoverCancelAcknowledgeIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverCancelAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelAcknowledgeIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelAcknowledgeIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverCancelAcknowledgeIEValue:", v.id)
	}
}

type HandoverFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v HandoverFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowMMEUES1APID != nil
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverFailureIEValue and reports whether the opaque alternative is selected.
func (v *HandoverFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverFailureIEs"}}
}
func (HandoverFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverFailureIEValue and reports whether that alternative is active.
func (v *HandoverFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsCause returns the selected Cause value of HandoverFailureIEValue and reports whether that alternative is active.
func (v *HandoverFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of HandoverFailureIEValue and reports whether that alternative is active.
func (v *HandoverFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v HandoverFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverFailureIEValue, error) {
	out := HandoverFailureIEValue{id: id}
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
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v HandoverFailureIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverFailureIEs.id-MME-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverFailureIEs.id-Cause:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverFailureIEValue:", v.id)
	}
}

type HandoverPreparationFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v HandoverPreparationFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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

// Opaque returns the retained opaque open value of HandoverPreparationFailureIEValue and reports whether the opaque alternative is selected.
func (v *HandoverPreparationFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverPreparationFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs"}}
}
func (HandoverPreparationFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverPreparationFailureIEValue and reports whether that alternative is active.
func (v *HandoverPreparationFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverPreparationFailureIEValue and reports whether that alternative is active.
func (v *HandoverPreparationFailureIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCause returns the selected Cause value of HandoverPreparationFailureIEValue and reports whether that alternative is active.
func (v *HandoverPreparationFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of HandoverPreparationFailureIEValue and reports whether that alternative is active.
func (v *HandoverPreparationFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v HandoverPreparationFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverPreparationFailureIEValue, error) {
	out := HandoverPreparationFailureIEValue{id: id}
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
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v HandoverPreparationFailureIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v HandoverPreparationFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverPreparationFailureIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverPreparationFailureIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverPreparationFailureIEs.id-Cause:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverPreparationFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverPreparationFailureIEValue:", v.id)
	}
}

type InitialContextSetupFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v InitialContextSetupFailureIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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

// Opaque returns the retained opaque open value of InitialContextSetupFailureIEValue and reports whether the opaque alternative is selected.
func (v *InitialContextSetupFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (InitialContextSetupFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs"}}
}
func (InitialContextSetupFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
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

// AsMMEUES1APID returns the selected MMEUES1APID value of InitialContextSetupFailureIEValue and reports whether that alternative is active.
func (v *InitialContextSetupFailureIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of InitialContextSetupFailureIEValue and reports whether that alternative is active.
func (v *InitialContextSetupFailureIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCause returns the selected Cause value of InitialContextSetupFailureIEValue and reports whether that alternative is active.
func (v *InitialContextSetupFailureIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of InitialContextSetupFailureIEValue and reports whether that alternative is active.
func (v *InitialContextSetupFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v InitialContextSetupFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InitialContextSetupFailureIEValue, error) {
	out := InitialContextSetupFailureIEValue{id: id}
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
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v InitialContextSetupFailureIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v InitialContextSetupFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupFailureIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupFailureIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupFailureIEs.id-Cause:")
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupFailureIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "InitialContextSetupFailureIEValue:", v.id)
	}
}

type MMEConfigurationUpdateAcknowledgeIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v MMEConfigurationUpdateAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEConfigurationUpdateAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *MMEConfigurationUpdateAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEConfigurationUpdateAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateAcknowledgeIEs"}}
}
func (MMEConfigurationUpdateAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of MMEConfigurationUpdateAcknowledgeIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateAcknowledgeIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v MMEConfigurationUpdateAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEConfigurationUpdateAcknowledgeIEValue, error) {
	out := MMEConfigurationUpdateAcknowledgeIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value CriticalityDiagnostics
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
func (v MMEConfigurationUpdateAcknowledgeIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v MMEConfigurationUpdateAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEConfigurationUpdateAcknowledgeIEValue:", v.id)
	}
}

type ENBConfigurationUpdateAcknowledgeIETable struct{}

func ENBConfigurationUpdateAcknowledgeIEs() ENBConfigurationUpdateAcknowledgeIETable {
	return ENBConfigurationUpdateAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of ENBConfigurationUpdateAcknowledgeIETable.
func (ENBConfigurationUpdateAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBConfigurationUpdateAcknowledgeIETable.
func (ENBConfigurationUpdateAcknowledgeIETable) Table() s00.ENBConfigurationUpdateAcknowledgeIEValueIETable {
	return func() s00.ENBConfigurationUpdateAcknowledgeIEValueIETable {
		sealed := s00.ENBConfigurationUpdateAcknowledgeIEValueIETable{}
		*s00.BridgeENBConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBConfigurationUpdateAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ENBConfigurationUpdateAcknowledgeIETable.
func (t ENBConfigurationUpdateAcknowledgeIETable) CriticalityDiagnostics() ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding {
	return ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero ENBConfigurationUpdateAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding ENBConfigurationUpdateAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) ENBConfigurationUpdateAcknowledgeIEValue {
		return ENBConfigurationUpdateAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *ENBConfigurationUpdateAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBConfigurationUpdateAcknowledgeIETable.
func (t ENBConfigurationUpdateAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBConfigurationUpdateAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(58):
		return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBConfigurationUpdateAcknowledgeIEField{Id: id, Criticality: criticality, Value: ENBConfigurationUpdateAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBConfigurationUpdateFailureIETable struct{}

func ENBConfigurationUpdateFailureIEs() ENBConfigurationUpdateFailureIETable {
	return ENBConfigurationUpdateFailureIETable{}
}

// ID returns the ASN.1 object-set identity of ENBConfigurationUpdateFailureIETable.
func (ENBConfigurationUpdateFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateFailureIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBConfigurationUpdateFailureIETable.
func (ENBConfigurationUpdateFailureIETable) Table() s00.ENBConfigurationUpdateFailureIEValueIETable {
	return func() s00.ENBConfigurationUpdateFailureIEValueIETable {
		sealed := s00.ENBConfigurationUpdateFailureIEValueIETable{}
		*s00.BridgeENBConfigurationUpdateFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBConfigurationUpdateFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateFailureIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of ENBConfigurationUpdateFailureIETable.
func (t ENBConfigurationUpdateFailureIETable) Cause() ENBConfigurationUpdateFailureCauseIEBinding {
	return ENBConfigurationUpdateFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding ENBConfigurationUpdateFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) ENBConfigurationUpdateFailureIEValue {
			return ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *ENBConfigurationUpdateFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (ENBConfigurationUpdateFailureIETable) infoTimeToWait() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(65), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeToWait"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateFailureIEs", Row: "id-TimeToWait"}}}
}

// TimeToWait returns the typed binding for the TimeToWait row of ENBConfigurationUpdateFailureIETable.
func (t ENBConfigurationUpdateFailureIETable) TimeToWait() ENBConfigurationUpdateFailureTimeToWaitIEBinding {
	return ENBConfigurationUpdateFailureTimeToWaitIEBinding{info: t.infoTimeToWait(), codec: func() s02.TimeToWaitValueCodec {
		sealed := s02.TimeToWaitValueCodec{}
		*s02.BridgeTimeToWaitValueCodecFieldPath(&sealed) = "TimeToWait"
		*s02.BridgeTimeToWaitValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeToWait, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(65), raw)
			if err != nil {
				var empty s00.TimeToWait
				return empty, err
			}
			value, ok := decoded.AsTimeToWait()
			if !ok {
				var empty s00.TimeToWait
				return empty, fmt.Errorf("binding ENBConfigurationUpdateFailureIEs.id-TimeToWait: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeToWaitValueCodecFieldEncode(&sealed) = func(value s00.TimeToWait, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.TimeToWait) ENBConfigurationUpdateFailureIEValue {
			return ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(65), rowTimeToWait: &value}
		}, get: func(value *ENBConfigurationUpdateFailureIEValue) (*s00.TimeToWait, bool) {
			return value.AsTimeToWait()
		}}
}
func (ENBConfigurationUpdateFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ENBConfigurationUpdateFailureIETable.
func (t ENBConfigurationUpdateFailureIETable) CriticalityDiagnostics() ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding {
	return ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding ENBConfigurationUpdateFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) ENBConfigurationUpdateFailureIEValue {
		return ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *ENBConfigurationUpdateFailureIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBConfigurationUpdateFailureIETable.
func (t ENBConfigurationUpdateFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBConfigurationUpdateFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(65):
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeToWait requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBConfigurationUpdateFailureIEField{Id: id, Criticality: criticality, Value: ENBConfigurationUpdateFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverCancelAcknowledgeIETable struct{}

func HandoverCancelAcknowledgeIEs() HandoverCancelAcknowledgeIETable {
	return HandoverCancelAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of HandoverCancelAcknowledgeIETable.
func (HandoverCancelAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverCancelAcknowledgeIETable.
func (HandoverCancelAcknowledgeIETable) Table() s00.HandoverCancelAcknowledgeIEValueIETable {
	return func() s00.HandoverCancelAcknowledgeIEValueIETable {
		sealed := s00.HandoverCancelAcknowledgeIEValueIETable{}
		*s00.BridgeHandoverCancelAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverCancelAcknowledgeIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverCancelAcknowledgeIETable.
func (t HandoverCancelAcknowledgeIETable) MMEUES1APID() HandoverCancelAcknowledgeMMEUES1APIDIEBinding {
	return HandoverCancelAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverCancelAcknowledgeIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverCancelAcknowledgeIEValue {
			return HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverCancelAcknowledgeIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverCancelAcknowledgeIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelAcknowledgeIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverCancelAcknowledgeIETable.
func (t HandoverCancelAcknowledgeIETable) ENBUES1APID() HandoverCancelAcknowledgeENBUES1APIDIEBinding {
	return HandoverCancelAcknowledgeENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverCancelAcknowledgeIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverCancelAcknowledgeIEValue {
			return HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverCancelAcknowledgeIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverCancelAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of HandoverCancelAcknowledgeIETable.
func (t HandoverCancelAcknowledgeIETable) CriticalityDiagnostics() HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding {
	return HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding HandoverCancelAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) HandoverCancelAcknowledgeIEValue {
		return HandoverCancelAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *HandoverCancelAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverCancelAcknowledgeIETable.
func (t HandoverCancelAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverCancelAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return HandoverCancelAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverCancelAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverCancelAcknowledgeIEField{Id: id, Criticality: criticality, Value: HandoverCancelAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverFailureIETable struct{}

func HandoverFailureIEs() HandoverFailureIETable { return HandoverFailureIETable{} }

// ID returns the ASN.1 object-set identity of HandoverFailureIETable.
func (HandoverFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverFailureIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverFailureIETable.
func (HandoverFailureIETable) Table() s00.HandoverFailureIEValueIETable {
	return func() s00.HandoverFailureIEValueIETable {
		sealed := s00.HandoverFailureIEValueIETable{}
		*s00.BridgeHandoverFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverFailureIETable.
func (t HandoverFailureIETable) MMEUES1APID() HandoverFailureMMEUES1APIDIEBinding {
	return HandoverFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverFailureIEValue {
			return HandoverFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverFailureIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of HandoverFailureIETable.
func (t HandoverFailureIETable) Cause() HandoverFailureCauseIEBinding {
	return HandoverFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding HandoverFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) HandoverFailureIEValue {
			return HandoverFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (HandoverFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of HandoverFailureIETable.
func (t HandoverFailureIETable) CriticalityDiagnostics() HandoverFailureCriticalityDiagnosticsIEBinding {
	return HandoverFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding HandoverFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) HandoverFailureIEValue {
		return HandoverFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *HandoverFailureIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverFailureIETable.
func (t HandoverFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverFailureIEField{Id: id, Criticality: criticality, Value: HandoverFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverPreparationFailureIETable struct{}

func HandoverPreparationFailureIEs() HandoverPreparationFailureIETable {
	return HandoverPreparationFailureIETable{}
}

// ID returns the ASN.1 object-set identity of HandoverPreparationFailureIETable.
func (HandoverPreparationFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverPreparationFailureIETable.
func (HandoverPreparationFailureIETable) Table() s00.HandoverPreparationFailureIEValueIETable {
	return func() s00.HandoverPreparationFailureIEValueIETable {
		sealed := s00.HandoverPreparationFailureIEValueIETable{}
		*s00.BridgeHandoverPreparationFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverPreparationFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverPreparationFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverPreparationFailureIETable.
func (t HandoverPreparationFailureIETable) MMEUES1APID() HandoverPreparationFailureMMEUES1APIDIEBinding {
	return HandoverPreparationFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverPreparationFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverPreparationFailureIEValue {
			return HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverPreparationFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverPreparationFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverPreparationFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverPreparationFailureIETable.
func (t HandoverPreparationFailureIETable) ENBUES1APID() HandoverPreparationFailureENBUES1APIDIEBinding {
	return HandoverPreparationFailureENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverPreparationFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverPreparationFailureIEValue {
			return HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverPreparationFailureIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverPreparationFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverPreparationFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of HandoverPreparationFailureIETable.
func (t HandoverPreparationFailureIETable) Cause() HandoverPreparationFailureCauseIEBinding {
	return HandoverPreparationFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding HandoverPreparationFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) HandoverPreparationFailureIEValue {
			return HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverPreparationFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (HandoverPreparationFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverPreparationFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverPreparationFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of HandoverPreparationFailureIETable.
func (t HandoverPreparationFailureIETable) CriticalityDiagnostics() HandoverPreparationFailureCriticalityDiagnosticsIEBinding {
	return HandoverPreparationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding HandoverPreparationFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) HandoverPreparationFailureIEValue {
		return HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *HandoverPreparationFailureIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverPreparationFailureIETable.
func (t HandoverPreparationFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverPreparationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverPreparationFailureIEField{Id: id, Criticality: criticality, Value: HandoverPreparationFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type InitialContextSetupFailureIETable struct{}

func InitialContextSetupFailureIEs() InitialContextSetupFailureIETable {
	return InitialContextSetupFailureIETable{}
}

// ID returns the ASN.1 object-set identity of InitialContextSetupFailureIETable.
func (InitialContextSetupFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InitialContextSetupFailureIETable.
func (InitialContextSetupFailureIETable) Table() s00.InitialContextSetupFailureIEValueIETable {
	return func() s00.InitialContextSetupFailureIEValueIETable {
		sealed := s00.InitialContextSetupFailureIEValueIETable{}
		*s00.BridgeInitialContextSetupFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (InitialContextSetupFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of InitialContextSetupFailureIETable.
func (t InitialContextSetupFailureIETable) MMEUES1APID() InitialContextSetupFailureMMEUES1APIDIEBinding {
	return InitialContextSetupFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding InitialContextSetupFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) InitialContextSetupFailureIEValue {
			return InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *InitialContextSetupFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (InitialContextSetupFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of InitialContextSetupFailureIETable.
func (t InitialContextSetupFailureIETable) ENBUES1APID() InitialContextSetupFailureENBUES1APIDIEBinding {
	return InitialContextSetupFailureENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding InitialContextSetupFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) InitialContextSetupFailureIEValue {
			return InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *InitialContextSetupFailureIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (InitialContextSetupFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of InitialContextSetupFailureIETable.
func (t InitialContextSetupFailureIETable) Cause() InitialContextSetupFailureCauseIEBinding {
	return InitialContextSetupFailureCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding InitialContextSetupFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) InitialContextSetupFailureIEValue {
			return InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *InitialContextSetupFailureIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (InitialContextSetupFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of InitialContextSetupFailureIETable.
func (t InitialContextSetupFailureIETable) CriticalityDiagnostics() InitialContextSetupFailureCriticalityDiagnosticsIEBinding {
	return InitialContextSetupFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding InitialContextSetupFailureIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) InitialContextSetupFailureIEValue {
		return InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *InitialContextSetupFailureIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InitialContextSetupFailureIETable.
func (t InitialContextSetupFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (InitialContextSetupFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return InitialContextSetupFailureIEField{Id: id, Criticality: criticality, Value: InitialContextSetupFailureIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEConfigurationUpdateAcknowledgeIETable struct{}

func MMEConfigurationUpdateAcknowledgeIEs() MMEConfigurationUpdateAcknowledgeIETable {
	return MMEConfigurationUpdateAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of MMEConfigurationUpdateAcknowledgeIETable.
func (MMEConfigurationUpdateAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEConfigurationUpdateAcknowledgeIETable.
func (MMEConfigurationUpdateAcknowledgeIETable) Table() s00.MMEConfigurationUpdateAcknowledgeIEValueIETable {
	return func() s00.MMEConfigurationUpdateAcknowledgeIEValueIETable {
		sealed := s00.MMEConfigurationUpdateAcknowledgeIEValueIETable{}
		*s00.BridgeMMEConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEConfigurationUpdateAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of MMEConfigurationUpdateAcknowledgeIETable.
func (t MMEConfigurationUpdateAcknowledgeIETable) CriticalityDiagnostics() MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding {
	return MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: CriticalityDiagnosticsValueCodec{path: "CriticalityDiagnostics",
		decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			var zero MMEConfigurationUpdateAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty CriticalityDiagnostics
				return empty, fmt.Errorf("binding MMEConfigurationUpdateAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		},
		encode: func(value CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}, capture: func(v CriticalityDiagnostics, options aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value CriticalityDiagnostics) MMEConfigurationUpdateAcknowledgeIEValue {
		return MMEConfigurationUpdateAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
	}, get: func(value *MMEConfigurationUpdateAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
		return value.AsCriticalityDiagnostics()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEConfigurationUpdateAcknowledgeIETable.
func (t MMEConfigurationUpdateAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEConfigurationUpdateAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(58):
		return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEConfigurationUpdateAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEConfigurationUpdateAcknowledgeIEField{Id: id, Criticality: criticality, Value: MMEConfigurationUpdateAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CellActivationRequestCodec binds the complete source value type.
func CellActivationRequestCodec() CellActivationRequestValueCodec {
	return CellActivationRequestValueCodec{path: "CellActivationRequest", decode: func(data []byte, options aper.DecodeState) (CellActivationRequest, error) {
		var value CellActivationRequest
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellActivationRequest{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellActivationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellActivationRequest, options aper.DecodeState) (CellActivationRequest, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellActivationRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v CellActivationRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellActivationRequest(&v, &s)
		s.End(f, root, false)

		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellActivationRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellBasedMDTCodec binds the complete source value type.
func CellBasedMDTCodec() CellBasedMDTValueCodec {
	return CellBasedMDTValueCodec{path: "CellBasedMDT", decode: func(data []byte, options aper.DecodeState) (CellBasedMDT, error) {
		var value CellBasedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellBasedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellBasedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellBasedMDT, options aper.DecodeState) (CellBasedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellBasedMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellBasedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellBasedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellBasedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellBasedQMCCodec binds the complete source value type.
func CellBasedQMCCodec() CellBasedQMCValueCodec {
	return CellBasedQMCValueCodec{path: "CellBasedQMC", decode: func(data []byte, options aper.DecodeState) (CellBasedQMC, error) {
		var value CellBasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellBasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellBasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellBasedQMC, options aper.DecodeState) (CellBasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellBasedQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellBasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellBasedQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellBasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EmergencyAreaIDBroadcastItemCodec binds the complete source value type.
func EmergencyAreaIDBroadcastItemCodec() EmergencyAreaIDBroadcastItemValueCodec {
	return EmergencyAreaIDBroadcastItemValueCodec{path: "EmergencyAreaIDBroadcastItem", decode: func(data []byte, options aper.DecodeState) (EmergencyAreaIDBroadcastItem, error) {
		var value EmergencyAreaIDBroadcastItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EmergencyAreaIDBroadcastItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EmergencyAreaIDBroadcastItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EmergencyAreaIDBroadcastItem, options aper.DecodeState) (EmergencyAreaIDBroadcastItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEmergencyAreaIDBroadcastItem(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v EmergencyAreaIDBroadcastItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APEmergencyAreaIDBroadcastItem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDBroadcastItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EmergencyAreaIDCancelledItemCodec binds the complete source value type.
func EmergencyAreaIDCancelledItemCodec() EmergencyAreaIDCancelledItemValueCodec {
	return EmergencyAreaIDCancelledItemValueCodec{path: "EmergencyAreaIDCancelledItem", decode: func(data []byte, options aper.DecodeState) (EmergencyAreaIDCancelledItem, error) {
		var value EmergencyAreaIDCancelledItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EmergencyAreaIDCancelledItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EmergencyAreaIDCancelledItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EmergencyAreaIDCancelledItem, options aper.DecodeState) (EmergencyAreaIDCancelledItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEmergencyAreaIDCancelledItem(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v EmergencyAreaIDCancelledItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APEmergencyAreaIDCancelledItem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDCancelledItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// HOReportCodec binds the complete source value type.
func HOReportCodec() HOReportValueCodec {
	return HOReportValueCodec{path: "HOReport", decode: func(data []byte, options aper.DecodeState) (HOReport, error) {
		var value HOReport
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return HOReport{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value HOReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v HOReport, options aper.DecodeState) (HOReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APHOReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HOReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APHOReport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HOReport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeCellActivationRequestAPERValueFieldContext(v *CellActivationRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellActivationRequestAPERValueFieldReceived(v *CellActivationRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellActivationRequestAPERValueFieldReplay(v *CellActivationRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellActivationRequestAPERValueFieldWithoutReplay(v *CellActivationRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellActivationRequestFieldCellsToActivateListIndef(v *CellActivationRequest) *bool {
	return &v.cellsToActivateListIndef
}
func BridgeCellActivationRequestFieldExtCount(v *CellActivationRequest) *int64   { return &v.extCount }
func BridgeCellActivationRequestFieldExtData(v *CellActivationRequest) *[][]byte { return &v.extData }
func BridgeCellActivationRequestFieldExtOrigin(v *CellActivationRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCellActivationRequestFieldExtPresent(v *CellActivationRequest) *[]bool {
	return &v.extPresent
}
func BridgeCellActivationRequestFieldExtWire(v *CellActivationRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCellActivationRequestFieldPerExtPadding(v *CellActivationRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellActivationRequestFieldPerPadding(v *CellActivationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellActivationRequestFieldReceived(v *CellActivationRequest) *bool { return &v.received }
func BridgeCellActivationRequestFieldReceivedAbsolute(v *CellActivationRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeCellActivationRequestFieldReceivedBytes(v *CellActivationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellActivationRequestFieldReceivedLocation(v *CellActivationRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellActivationRequestFieldReplay(v *CellActivationRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeCellActivationRequestFieldStream(v *CellActivationRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeCellActivationRequestFieldWithoutReplay(v *CellActivationRequest) *bool {
	return &v.withoutReplay
}
func BridgeCellActivationRequestMethodMarshalAPERBudget(v *CellActivationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellActivationRequestMethodMarshalAPERBudgetValue(v *CellActivationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellActivationRequestMethodMarshalAPERChanged(v *CellActivationRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellActivationRequestMethodMarshalAPERChangedValue(v *CellActivationRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellActivationRequestMethodMarshalAPERLegacy(v *CellActivationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellActivationRequestMethodMarshalAPERNewValue(v *CellActivationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellActivationRequestMethodMarshalAPERPlanned(v *CellActivationRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellActivationRequestMethodMarshalAPERTo(v *CellActivationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellActivationRequestMethodUnmarshalAPERFrom(v *CellActivationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellActivationRequestMethodUnmarshalAPERLegacy(v *CellActivationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellActivationRequestMethodUnmarshalAPERWithOptions(v *CellActivationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellActivationRequestValueCodecFieldCapture(v *CellActivationRequestValueCodec) *func(CellActivationRequest, aper.DecodeState) (CellActivationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeCellActivationRequestValueCodecFieldCompare(v *CellActivationRequestValueCodec) *func(CellActivationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellActivationRequestValueCodecFieldContext(v *CellActivationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellActivationRequestValueCodecFieldDecode(v *CellActivationRequestValueCodec) *func([]byte, aper.DecodeState) (CellActivationRequest, error) {
	return &v.decode
}
func BridgeCellActivationRequestValueCodecFieldEncode(v *CellActivationRequestValueCodec) *func(CellActivationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellActivationRequestValueCodecFieldPath(v *CellActivationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellActivationRequestValueCodecMethodEncodeBudgetValue(v CellActivationRequestValueCodec, a0 CellActivationRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellActivationRequestValueCodecMethodEncodeChanged(v CellActivationRequestValueCodec, a0 CellActivationRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellBasedMDTAPERValueFieldContext(v *CellBasedMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedMDTAPERValueFieldReceived(v *CellBasedMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellBasedMDTAPERValueFieldReplay(v *CellBasedMDTAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellBasedMDTAPERValueFieldWithoutReplay(v *CellBasedMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellBasedMDTFieldCellIdListforMDTIndef(v *CellBasedMDT) *bool {
	return &v.cellIdListforMDTIndef
}
func BridgeCellBasedMDTFieldExtCount(v *CellBasedMDT) *int64                { return &v.extCount }
func BridgeCellBasedMDTFieldExtData(v *CellBasedMDT) *[][]byte              { return &v.extData }
func BridgeCellBasedMDTFieldExtOrigin(v *CellBasedMDT) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeCellBasedMDTFieldExtPresent(v *CellBasedMDT) *[]bool             { return &v.extPresent }
func BridgeCellBasedMDTFieldExtWire(v *CellBasedMDT) *[]aper.WireSpan       { return &v.extWire }
func BridgeCellBasedMDTFieldIEExtensionsIndef(v *CellBasedMDT) *bool        { return &v.iEExtensionsIndef }
func BridgeCellBasedMDTFieldPerExtPadding(v *CellBasedMDT) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellBasedMDTFieldPerPadding(v *CellBasedMDT) *aper.FinalPadding { return &v.perPadding }
func BridgeCellBasedMDTFieldReceived(v *CellBasedMDT) *bool                { return &v.received }
func BridgeCellBasedMDTFieldReceivedAbsolute(v *CellBasedMDT) *bool        { return &v.receivedAbsolute }
func BridgeCellBasedMDTFieldReceivedBytes(v *CellBasedMDT) *aper.WireSpan  { return &v.receivedBytes }
func BridgeCellBasedMDTFieldReceivedLocation(v *CellBasedMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellBasedMDTFieldReplay(v *CellBasedMDT) *aper.Snapshot { return &v.replay }
func BridgeCellBasedMDTFieldStream(v *CellBasedMDT) *aper.WireSpan { return &v.stream }
func BridgeCellBasedMDTFieldWithoutReplay(v *CellBasedMDT) *bool   { return &v.withoutReplay }
func BridgeCellBasedMDTMethodMarshalAPERBudget(v *CellBasedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellBasedMDTMethodMarshalAPERBudgetValue(v *CellBasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellBasedMDTMethodMarshalAPERChanged(v *CellBasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellBasedMDTMethodMarshalAPERChangedValue(v *CellBasedMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellBasedMDTMethodMarshalAPERLegacy(v *CellBasedMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellBasedMDTMethodMarshalAPERNewValue(v *CellBasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellBasedMDTMethodMarshalAPERPlanned(v *CellBasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellBasedMDTMethodMarshalAPERTo(v *CellBasedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedMDTMethodUnmarshalAPERFrom(v *CellBasedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellBasedMDTMethodUnmarshalAPERLegacy(v *CellBasedMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellBasedMDTMethodUnmarshalAPERWithOptions(v *CellBasedMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellBasedMDTValueCodecFieldCapture(v *CellBasedMDTValueCodec) *func(CellBasedMDT, aper.DecodeState) (CellBasedMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedMDTValueCodecFieldCompare(v *CellBasedMDTValueCodec) *func(CellBasedMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedMDTValueCodecFieldContext(v *CellBasedMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedMDTValueCodecFieldDecode(v *CellBasedMDTValueCodec) *func([]byte, aper.DecodeState) (CellBasedMDT, error) {
	return &v.decode
}
func BridgeCellBasedMDTValueCodecFieldEncode(v *CellBasedMDTValueCodec) *func(CellBasedMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedMDTValueCodecFieldPath(v *CellBasedMDTValueCodec) *aper.Path { return &v.path }
func BridgeCellBasedMDTValueCodecMethodEncodeBudgetValue(v CellBasedMDTValueCodec, a0 CellBasedMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellBasedMDTValueCodecMethodEncodeChanged(v CellBasedMDTValueCodec, a0 CellBasedMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellBasedQMCAPERValueFieldContext(v *CellBasedQMCAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedQMCAPERValueFieldReceived(v *CellBasedQMCAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellBasedQMCAPERValueFieldReplay(v *CellBasedQMCAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellBasedQMCAPERValueFieldWithoutReplay(v *CellBasedQMCAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellBasedQMCFieldCellIdListforQMCIndef(v *CellBasedQMC) *bool {
	return &v.cellIdListforQMCIndef
}
func BridgeCellBasedQMCFieldExtCount(v *CellBasedQMC) *int64                { return &v.extCount }
func BridgeCellBasedQMCFieldExtData(v *CellBasedQMC) *[][]byte              { return &v.extData }
func BridgeCellBasedQMCFieldExtOrigin(v *CellBasedQMC) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeCellBasedQMCFieldExtPresent(v *CellBasedQMC) *[]bool             { return &v.extPresent }
func BridgeCellBasedQMCFieldExtWire(v *CellBasedQMC) *[]aper.WireSpan       { return &v.extWire }
func BridgeCellBasedQMCFieldIEExtensionsIndef(v *CellBasedQMC) *bool        { return &v.iEExtensionsIndef }
func BridgeCellBasedQMCFieldPerExtPadding(v *CellBasedQMC) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellBasedQMCFieldPerPadding(v *CellBasedQMC) *aper.FinalPadding { return &v.perPadding }
func BridgeCellBasedQMCFieldReceived(v *CellBasedQMC) *bool                { return &v.received }
func BridgeCellBasedQMCFieldReceivedAbsolute(v *CellBasedQMC) *bool        { return &v.receivedAbsolute }
func BridgeCellBasedQMCFieldReceivedBytes(v *CellBasedQMC) *aper.WireSpan  { return &v.receivedBytes }
func BridgeCellBasedQMCFieldReceivedLocation(v *CellBasedQMC) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellBasedQMCFieldReplay(v *CellBasedQMC) *aper.Snapshot { return &v.replay }
func BridgeCellBasedQMCFieldStream(v *CellBasedQMC) *aper.WireSpan { return &v.stream }
func BridgeCellBasedQMCFieldWithoutReplay(v *CellBasedQMC) *bool   { return &v.withoutReplay }
func BridgeCellBasedQMCMethodMarshalAPERBudget(v *CellBasedQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellBasedQMCMethodMarshalAPERBudgetValue(v *CellBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellBasedQMCMethodMarshalAPERChanged(v *CellBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellBasedQMCMethodMarshalAPERChangedValue(v *CellBasedQMC, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellBasedQMCMethodMarshalAPERLegacy(v *CellBasedQMC) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellBasedQMCMethodMarshalAPERNewValue(v *CellBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellBasedQMCMethodMarshalAPERPlanned(v *CellBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellBasedQMCMethodMarshalAPERTo(v *CellBasedQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedQMCMethodUnmarshalAPERFrom(v *CellBasedQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellBasedQMCMethodUnmarshalAPERLegacy(v *CellBasedQMC, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellBasedQMCMethodUnmarshalAPERWithOptions(v *CellBasedQMC, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellBasedQMCValueCodecFieldCapture(v *CellBasedQMCValueCodec) *func(CellBasedQMC, aper.DecodeState) (CellBasedQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeCellBasedQMCValueCodecFieldCompare(v *CellBasedQMCValueCodec) *func(CellBasedQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellBasedQMCValueCodecFieldContext(v *CellBasedQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellBasedQMCValueCodecFieldDecode(v *CellBasedQMCValueCodec) *func([]byte, aper.DecodeState) (CellBasedQMC, error) {
	return &v.decode
}
func BridgeCellBasedQMCValueCodecFieldEncode(v *CellBasedQMCValueCodec) *func(CellBasedQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellBasedQMCValueCodecFieldPath(v *CellBasedQMCValueCodec) *aper.Path { return &v.path }
func BridgeCellBasedQMCValueCodecMethodEncodeBudgetValue(v CellBasedQMCValueCodec, a0 CellBasedQMC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellBasedQMCValueCodecMethodEncodeChanged(v CellBasedQMCValueCodec, a0 CellBasedQMC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsAPERValueFieldContext(v *CriticalityDiagnosticsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsAPERValueFieldReceived(v *CriticalityDiagnosticsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsAPERValueFieldReplay(v *CriticalityDiagnosticsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsFieldExtCount(v *CriticalityDiagnostics) *int64   { return &v.extCount }
func BridgeCriticalityDiagnosticsFieldExtData(v *CriticalityDiagnostics) *[][]byte { return &v.extData }
func BridgeCriticalityDiagnosticsFieldExtOrigin(v *CriticalityDiagnostics) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCriticalityDiagnosticsFieldExtPresent(v *CriticalityDiagnostics) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsFieldExtWire(v *CriticalityDiagnostics) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCriticalityDiagnosticsFieldIEExtensionsIndef(v *CriticalityDiagnostics) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCriticalityDiagnosticsFieldIEsCriticalityDiagnosticsIndef(v *CriticalityDiagnostics) *bool {
	return &v.iEsCriticalityDiagnosticsIndef
}
func BridgeCriticalityDiagnosticsFieldPerExtPadding(v *CriticalityDiagnostics) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCriticalityDiagnosticsFieldPerPadding(v *CriticalityDiagnostics) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsFieldReceived(v *CriticalityDiagnostics) *bool { return &v.received }
func BridgeCriticalityDiagnosticsFieldReceivedAbsolute(v *CriticalityDiagnostics) *bool {
	return &v.receivedAbsolute
}
func BridgeCriticalityDiagnosticsFieldReceivedBytes(v *CriticalityDiagnostics) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsFieldReceivedLocation(v *CriticalityDiagnostics) *aper.Location {
	return &v.receivedLocation
}
func BridgeCriticalityDiagnosticsFieldReplay(v *CriticalityDiagnostics) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsFieldStream(v *CriticalityDiagnostics) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsFieldWithoutReplay(v *CriticalityDiagnostics) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERBudgetValue(v *CriticalityDiagnostics, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERChanged(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERChangedValue(v *CriticalityDiagnostics, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERLegacy(v *CriticalityDiagnostics) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERNewValue(v *CriticalityDiagnostics, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERPlanned(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERTo(v *CriticalityDiagnostics, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(v *CriticalityDiagnostics, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERLegacy(v *CriticalityDiagnostics, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERWithOptions(v *CriticalityDiagnostics, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCriticalityDiagnosticsValueCodecFieldCapture(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, aper.DecodeState) (CriticalityDiagnostics, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsValueCodecFieldCompare(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsValueCodecFieldContext(v *CriticalityDiagnosticsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsValueCodecFieldDecode(v *CriticalityDiagnosticsValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnostics, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsValueCodecFieldEncode(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsValueCodecFieldPath(v *CriticalityDiagnosticsValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeBudgetValue(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeChanged(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *func(*ENBConfigurationUpdateAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) ENBConfigurationUpdateAcknowledgeIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEContainer, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeIEContainerValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeIEContainerValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldStream(v *ENBConfigurationUpdateAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(v *ENBConfigurationUpdateAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEField, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEField, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeIEFieldValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeIEFieldValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeIETableMethodInfoCriticalityDiagnostics(v ENBConfigurationUpdateAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldId(v *ENBConfigurationUpdateAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(v *ENBConfigurationUpdateAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldOpaque(v *ENBConfigurationUpdateAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *ENBConfigurationUpdateAcknowledgeIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v ENBConfigurationUpdateAcknowledgeIEValue, a0 aper.SemanticCapture) ENBConfigurationUpdateAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v ENBConfigurationUpdateAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodDecode(v ENBConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBConfigurationUpdateAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodEncode(v ENBConfigurationUpdateAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodEncodeFresh(v ENBConfigurationUpdateAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodMatchesID(v ENBConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodReason(v ENBConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodRule(v ENBConfigurationUpdateAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureCauseIEBindingFieldCodec(v *ENBConfigurationUpdateFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateFailureCauseIEBindingFieldGet(v *ENBConfigurationUpdateFailureCauseIEBinding) *func(*ENBConfigurationUpdateFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateFailureCauseIEBindingFieldInfo(v *ENBConfigurationUpdateFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateFailureCauseIEBindingFieldInject(v *ENBConfigurationUpdateFailureCauseIEBinding) *func(s14.Cause) ENBConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldCodec(v *ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldGet(v *ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *func(*ENBConfigurationUpdateFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldInfo(v *ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateFailureCriticalityDiagnosticsIEBindingFieldInject(v *ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) ENBConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateFailureIEContainerAPERValueFieldContext(v *ENBConfigurationUpdateFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEContainerAPERValueFieldReceived(v *ENBConfigurationUpdateFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEContainerAPERValueFieldReplay(v *ENBConfigurationUpdateFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEContainerAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCapture(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *func(ENBConfigurationUpdateFailureIEContainer, aper.DecodeState) (ENBConfigurationUpdateFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCompare(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *func(ENBConfigurationUpdateFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldContext(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEContainer, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *func(ENBConfigurationUpdateFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldPath(v *ENBConfigurationUpdateFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureIEContainerValueCodec, a0 ENBConfigurationUpdateFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureIEContainerValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureIEContainerValueCodec, a0 ENBConfigurationUpdateFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureIEFieldAPERValueFieldContext(v *ENBConfigurationUpdateFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEFieldAPERValueFieldReceived(v *ENBConfigurationUpdateFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEFieldAPERValueFieldReplay(v *ENBConfigurationUpdateFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEFieldAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEFieldFieldReceived(v *ENBConfigurationUpdateFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v *ENBConfigurationUpdateFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEFieldFieldStream(v *ENBConfigurationUpdateFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateFailureIEFieldFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(v *ENBConfigurationUpdateFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCapture(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *func(ENBConfigurationUpdateFailureIEField, aper.DecodeState) (ENBConfigurationUpdateFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCompare(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *func(ENBConfigurationUpdateFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldContext(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldDecode(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEField, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldEncode(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *func(ENBConfigurationUpdateFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldPath(v *ENBConfigurationUpdateFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureIEFieldValueCodec, a0 ENBConfigurationUpdateFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureIEFieldValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureIEFieldValueCodec, a0 ENBConfigurationUpdateFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureIETableMethodInfoCause(v ENBConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeENBConfigurationUpdateFailureIETableMethodInfoCriticalityDiagnostics(v ENBConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeENBConfigurationUpdateFailureIETableMethodInfoTimeToWait(v ENBConfigurationUpdateFailureIETable) s00.FieldInfo {
	return v.infoTimeToWait()
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureIEValueFieldId(v *ENBConfigurationUpdateFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateFailureIEValueFieldIsOpaque(v *ENBConfigurationUpdateFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateFailureIEValueFieldOpaque(v *ENBConfigurationUpdateFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationUpdateFailureIEValueFieldReceived(v *ENBConfigurationUpdateFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEValueFieldReplay(v *ENBConfigurationUpdateFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEValueFieldRowCause(v *ENBConfigurationUpdateFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeENBConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(v *ENBConfigurationUpdateFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeENBConfigurationUpdateFailureIEValueFieldRowTimeToWait(v *ENBConfigurationUpdateFailureIEValue) **s00.TimeToWait {
	return &v.rowTimeToWait
}
func BridgeENBConfigurationUpdateFailureIEValueMethodCaptureSemantics(v ENBConfigurationUpdateFailureIEValue, a0 aper.SemanticCapture) ENBConfigurationUpdateFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodCompareSemantics(v ENBConfigurationUpdateFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodDecode(v ENBConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBConfigurationUpdateFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodEncode(v ENBConfigurationUpdateFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBConfigurationUpdateFailureIEValueMethodEncodeFresh(v ENBConfigurationUpdateFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodMatchesID(v ENBConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodReason(v ENBConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodRule(v ENBConfigurationUpdateFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateFailureTimeToWaitIEBindingFieldCodec(v *ENBConfigurationUpdateFailureTimeToWaitIEBinding) *s02.TimeToWaitValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateFailureTimeToWaitIEBindingFieldGet(v *ENBConfigurationUpdateFailureTimeToWaitIEBinding) *func(*ENBConfigurationUpdateFailureIEValue) (*s00.TimeToWait, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateFailureTimeToWaitIEBindingFieldInfo(v *ENBConfigurationUpdateFailureTimeToWaitIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateFailureTimeToWaitIEBindingFieldInject(v *ENBConfigurationUpdateFailureTimeToWaitIEBinding) *func(s00.TimeToWait) ENBConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeEmergencyAreaIDBroadcastAPERValueFieldContext(v *EmergencyAreaIDBroadcastAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastAPERValueFieldReceived(v *EmergencyAreaIDBroadcastAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEmergencyAreaIDBroadcastAPERValueFieldReplay(v *EmergencyAreaIDBroadcastAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDBroadcastAPERValueFieldWithoutReplay(v *EmergencyAreaIDBroadcastAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDBroadcastItemAPERValueFieldContext(v *EmergencyAreaIDBroadcastItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastItemAPERValueFieldReceived(v *EmergencyAreaIDBroadcastItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEmergencyAreaIDBroadcastItemAPERValueFieldReplay(v *EmergencyAreaIDBroadcastItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDBroadcastItemAPERValueFieldWithoutReplay(v *EmergencyAreaIDBroadcastItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDBroadcastItemFieldCompletedCellinEAIIndef(v *EmergencyAreaIDBroadcastItem) *bool {
	return &v.completedCellinEAIIndef
}
func BridgeEmergencyAreaIDBroadcastItemFieldExtCount(v *EmergencyAreaIDBroadcastItem) *int64 {
	return &v.extCount
}
func BridgeEmergencyAreaIDBroadcastItemFieldExtData(v *EmergencyAreaIDBroadcastItem) *[][]byte {
	return &v.extData
}
func BridgeEmergencyAreaIDBroadcastItemFieldExtOrigin(v *EmergencyAreaIDBroadcastItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEmergencyAreaIDBroadcastItemFieldExtPresent(v *EmergencyAreaIDBroadcastItem) *[]bool {
	return &v.extPresent
}
func BridgeEmergencyAreaIDBroadcastItemFieldExtWire(v *EmergencyAreaIDBroadcastItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEmergencyAreaIDBroadcastItemFieldIEExtensionsIndef(v *EmergencyAreaIDBroadcastItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeEmergencyAreaIDBroadcastItemFieldPerExtPadding(v *EmergencyAreaIDBroadcastItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEmergencyAreaIDBroadcastItemFieldPerPadding(v *EmergencyAreaIDBroadcastItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDBroadcastItemFieldReceived(v *EmergencyAreaIDBroadcastItem) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDBroadcastItemFieldReceivedAbsolute(v *EmergencyAreaIDBroadcastItem) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDBroadcastItemFieldReceivedBytes(v *EmergencyAreaIDBroadcastItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDBroadcastItemFieldReceivedLocation(v *EmergencyAreaIDBroadcastItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDBroadcastItemFieldReplay(v *EmergencyAreaIDBroadcastItem) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDBroadcastItemFieldStream(v *EmergencyAreaIDBroadcastItem) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDBroadcastItemFieldWithoutReplay(v *EmergencyAreaIDBroadcastItem) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERBudget(v *EmergencyAreaIDBroadcastItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERBudgetValue(v *EmergencyAreaIDBroadcastItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERChanged(v *EmergencyAreaIDBroadcastItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERChangedValue(v *EmergencyAreaIDBroadcastItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERLegacy(v *EmergencyAreaIDBroadcastItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERNewValue(v *EmergencyAreaIDBroadcastItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERPlanned(v *EmergencyAreaIDBroadcastItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERTo(v *EmergencyAreaIDBroadcastItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERFrom(v *EmergencyAreaIDBroadcastItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERLegacy(v *EmergencyAreaIDBroadcastItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDBroadcastItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldCapture(v *EmergencyAreaIDBroadcastItemValueCodec) *func(EmergencyAreaIDBroadcastItem, aper.DecodeState) (EmergencyAreaIDBroadcastItem, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldCompare(v *EmergencyAreaIDBroadcastItemValueCodec) *func(EmergencyAreaIDBroadcastItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldContext(v *EmergencyAreaIDBroadcastItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldDecode(v *EmergencyAreaIDBroadcastItemValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcastItem, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldEncode(v *EmergencyAreaIDBroadcastItemValueCodec) *func(EmergencyAreaIDBroadcastItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecFieldPath(v *EmergencyAreaIDBroadcastItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecMethodEncodeBudgetValue(v EmergencyAreaIDBroadcastItemValueCodec, a0 EmergencyAreaIDBroadcastItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastItemValueCodecMethodEncodeChanged(v EmergencyAreaIDBroadcastItemValueCodec, a0 EmergencyAreaIDBroadcastItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldCapture(v *EmergencyAreaIDBroadcastValueCodec) *func(EmergencyAreaIDBroadcast, aper.DecodeState) (EmergencyAreaIDBroadcast, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldCompare(v *EmergencyAreaIDBroadcastValueCodec) *func(EmergencyAreaIDBroadcast, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldContext(v *EmergencyAreaIDBroadcastValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldDecode(v *EmergencyAreaIDBroadcastValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDBroadcast, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldEncode(v *EmergencyAreaIDBroadcastValueCodec) *func(EmergencyAreaIDBroadcast, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDBroadcastValueCodecFieldPath(v *EmergencyAreaIDBroadcastValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDBroadcastValueCodecMethodEncodeBudgetValue(v EmergencyAreaIDBroadcastValueCodec, a0 EmergencyAreaIDBroadcast, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastValueCodecMethodEncodeChanged(v EmergencyAreaIDBroadcastValueCodec, a0 EmergencyAreaIDBroadcast, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEmergencyAreaIDCancelledAPERValueFieldContext(v *EmergencyAreaIDCancelledAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledAPERValueFieldReceived(v *EmergencyAreaIDCancelledAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEmergencyAreaIDCancelledAPERValueFieldReplay(v *EmergencyAreaIDCancelledAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDCancelledAPERValueFieldWithoutReplay(v *EmergencyAreaIDCancelledAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDCancelledItemAPERValueFieldContext(v *EmergencyAreaIDCancelledItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledItemAPERValueFieldReceived(v *EmergencyAreaIDCancelledItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEmergencyAreaIDCancelledItemAPERValueFieldReplay(v *EmergencyAreaIDCancelledItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDCancelledItemAPERValueFieldWithoutReplay(v *EmergencyAreaIDCancelledItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDCancelledItemFieldCancelledCellinEAIIndef(v *EmergencyAreaIDCancelledItem) *bool {
	return &v.cancelledCellinEAIIndef
}
func BridgeEmergencyAreaIDCancelledItemFieldExtCount(v *EmergencyAreaIDCancelledItem) *int64 {
	return &v.extCount
}
func BridgeEmergencyAreaIDCancelledItemFieldExtData(v *EmergencyAreaIDCancelledItem) *[][]byte {
	return &v.extData
}
func BridgeEmergencyAreaIDCancelledItemFieldExtOrigin(v *EmergencyAreaIDCancelledItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEmergencyAreaIDCancelledItemFieldExtPresent(v *EmergencyAreaIDCancelledItem) *[]bool {
	return &v.extPresent
}
func BridgeEmergencyAreaIDCancelledItemFieldExtWire(v *EmergencyAreaIDCancelledItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEmergencyAreaIDCancelledItemFieldIEExtensionsIndef(v *EmergencyAreaIDCancelledItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeEmergencyAreaIDCancelledItemFieldPerExtPadding(v *EmergencyAreaIDCancelledItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEmergencyAreaIDCancelledItemFieldPerPadding(v *EmergencyAreaIDCancelledItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDCancelledItemFieldReceived(v *EmergencyAreaIDCancelledItem) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDCancelledItemFieldReceivedAbsolute(v *EmergencyAreaIDCancelledItem) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDCancelledItemFieldReceivedBytes(v *EmergencyAreaIDCancelledItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDCancelledItemFieldReceivedLocation(v *EmergencyAreaIDCancelledItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDCancelledItemFieldReplay(v *EmergencyAreaIDCancelledItem) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDCancelledItemFieldStream(v *EmergencyAreaIDCancelledItem) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDCancelledItemFieldWithoutReplay(v *EmergencyAreaIDCancelledItem) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERBudget(v *EmergencyAreaIDCancelledItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERBudgetValue(v *EmergencyAreaIDCancelledItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERChanged(v *EmergencyAreaIDCancelledItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERChangedValue(v *EmergencyAreaIDCancelledItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERLegacy(v *EmergencyAreaIDCancelledItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERNewValue(v *EmergencyAreaIDCancelledItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERPlanned(v *EmergencyAreaIDCancelledItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(v *EmergencyAreaIDCancelledItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERFrom(v *EmergencyAreaIDCancelledItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERLegacy(v *EmergencyAreaIDCancelledItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDCancelledItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldCapture(v *EmergencyAreaIDCancelledItemValueCodec) *func(EmergencyAreaIDCancelledItem, aper.DecodeState) (EmergencyAreaIDCancelledItem, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldCompare(v *EmergencyAreaIDCancelledItemValueCodec) *func(EmergencyAreaIDCancelledItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldContext(v *EmergencyAreaIDCancelledItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldDecode(v *EmergencyAreaIDCancelledItemValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItem, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldEncode(v *EmergencyAreaIDCancelledItemValueCodec) *func(EmergencyAreaIDCancelledItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDCancelledItemValueCodecFieldPath(v *EmergencyAreaIDCancelledItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDCancelledItemValueCodecMethodEncodeBudgetValue(v EmergencyAreaIDCancelledItemValueCodec, a0 EmergencyAreaIDCancelledItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledItemValueCodecMethodEncodeChanged(v EmergencyAreaIDCancelledItemValueCodec, a0 EmergencyAreaIDCancelledItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldCapture(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, aper.DecodeState) (EmergencyAreaIDCancelled, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldCompare(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldContext(v *EmergencyAreaIDCancelledValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldDecode(v *EmergencyAreaIDCancelledValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDCancelled, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldEncode(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldPath(v *EmergencyAreaIDCancelledValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDCancelledValueCodecMethodEncodeBudgetValue(v EmergencyAreaIDCancelledValueCodec, a0 EmergencyAreaIDCancelled, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledValueCodecMethodEncodeChanged(v EmergencyAreaIDCancelledValueCodec, a0 EmergencyAreaIDCancelled, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHOReportAPERValueFieldContext(v *HOReportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHOReportAPERValueFieldReceived(v *HOReportAPERValue) *aper.WireSpan { return &v.received }
func BridgeHOReportAPERValueFieldReplay(v *HOReportAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeHOReportAPERValueFieldWithoutReplay(v *HOReportAPERValue) *bool     { return &v.withoutReplay }
func BridgeHOReportFieldCandidateCellListIndef(v *HOReport) *bool              { return &v.candidateCellListIndef }
func BridgeHOReportFieldCandidatePCIListIndef(v *HOReport) *bool               { return &v.candidatePCIListIndef }
func BridgeHOReportFieldExtCount(v *HOReport) *int64                           { return &v.extCount }
func BridgeHOReportFieldExtData(v *HOReport) *[][]byte                         { return &v.extData }
func BridgeHOReportFieldExtOrigin(v *HOReport) *[]aper.OpaqueOrigin            { return &v.extOrigin }
func BridgeHOReportFieldExtPresent(v *HOReport) *[]bool                        { return &v.extPresent }
func BridgeHOReportFieldExtWire(v *HOReport) *[]aper.WireSpan                  { return &v.extWire }
func BridgeHOReportFieldPerExtPadding(v *HOReport) *[]aper.CompletePadding     { return &v.perExtPadding }
func BridgeHOReportFieldPerPadding(v *HOReport) *aper.FinalPadding             { return &v.perPadding }
func BridgeHOReportFieldReceived(v *HOReport) *bool                            { return &v.received }
func BridgeHOReportFieldReceivedAbsolute(v *HOReport) *bool                    { return &v.receivedAbsolute }
func BridgeHOReportFieldReceivedBytes(v *HOReport) *aper.WireSpan              { return &v.receivedBytes }
func BridgeHOReportFieldReceivedLocation(v *HOReport) *aper.Location           { return &v.receivedLocation }
func BridgeHOReportFieldReplay(v *HOReport) *aper.Snapshot                     { return &v.replay }
func BridgeHOReportFieldStream(v *HOReport) *aper.WireSpan                     { return &v.stream }
func BridgeHOReportFieldWithoutReplay(v *HOReport) *bool                       { return &v.withoutReplay }
func BridgeHOReportMethodMarshalAPERBudget(v *HOReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHOReportMethodMarshalAPERBudgetValue(v *HOReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHOReportMethodMarshalAPERChanged(v *HOReport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHOReportMethodMarshalAPERChangedValue(v *HOReport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHOReportMethodMarshalAPERLegacy(v *HOReport) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeHOReportMethodMarshalAPERNewValue(v *HOReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHOReportMethodMarshalAPERPlanned(v *HOReport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHOReportMethodMarshalAPERTo(v *HOReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHOReportMethodUnmarshalAPERFrom(v *HOReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHOReportMethodUnmarshalAPERLegacy(v *HOReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHOReportMethodUnmarshalAPERWithOptions(v *HOReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHOReportValueCodecFieldCapture(v *HOReportValueCodec) *func(HOReport, aper.DecodeState) (HOReport, aper.Snapshot) {
	return &v.capture
}
func BridgeHOReportValueCodecFieldCompare(v *HOReportValueCodec) *func(HOReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHOReportValueCodecFieldContext(v *HOReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHOReportValueCodecFieldDecode(v *HOReportValueCodec) *func([]byte, aper.DecodeState) (HOReport, error) {
	return &v.decode
}
func BridgeHOReportValueCodecFieldEncode(v *HOReportValueCodec) *func(HOReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHOReportValueCodecFieldPath(v *HOReportValueCodec) *aper.Path { return &v.path }
func BridgeHOReportValueCodecMethodEncodeBudgetValue(v HOReportValueCodec, a0 HOReport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHOReportValueCodecMethodEncodeChanged(v HOReportValueCodec, a0 HOReport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeHandoverCancelAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) *func(*HandoverCancelAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeHandoverCancelAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) HandoverCancelAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverCancelAcknowledgeENBUES1APIDIEBindingFieldCodec(v *HandoverCancelAcknowledgeENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCancelAcknowledgeENBUES1APIDIEBindingFieldGet(v *HandoverCancelAcknowledgeENBUES1APIDIEBinding) *func(*HandoverCancelAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCancelAcknowledgeENBUES1APIDIEBindingFieldInfo(v *HandoverCancelAcknowledgeENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelAcknowledgeENBUES1APIDIEBindingFieldInject(v *HandoverCancelAcknowledgeENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverCancelAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverCancelAcknowledgeIEContainerAPERValueFieldContext(v *HandoverCancelAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEContainerAPERValueFieldReceived(v *HandoverCancelAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEContainerAPERValueFieldReplay(v *HandoverCancelAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCapture(v *HandoverCancelAcknowledgeIEContainerValueCodec) *func(HandoverCancelAcknowledgeIEContainer, aper.DecodeState) (HandoverCancelAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldCompare(v *HandoverCancelAcknowledgeIEContainerValueCodec) *func(HandoverCancelAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldContext(v *HandoverCancelAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldDecode(v *HandoverCancelAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldEncode(v *HandoverCancelAcknowledgeIEContainerValueCodec) *func(HandoverCancelAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecFieldPath(v *HandoverCancelAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeIEContainerValueCodec, a0 HandoverCancelAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeIEContainerValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeIEContainerValueCodec, a0 HandoverCancelAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeIEFieldAPERValueFieldContext(v *HandoverCancelAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEFieldAPERValueFieldReceived(v *HandoverCancelAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEFieldAPERValueFieldReplay(v *HandoverCancelAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEFieldFieldReceived(v *HandoverCancelAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v *HandoverCancelAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEFieldFieldStream(v *HandoverCancelAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverCancelAcknowledgeIEFieldFieldWithoutReplay(v *HandoverCancelAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(v *HandoverCancelAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCancelAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *HandoverCancelAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCapture(v *HandoverCancelAcknowledgeIEFieldValueCodec) *func(HandoverCancelAcknowledgeIEField, aper.DecodeState) (HandoverCancelAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldCompare(v *HandoverCancelAcknowledgeIEFieldValueCodec) *func(HandoverCancelAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldContext(v *HandoverCancelAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldDecode(v *HandoverCancelAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEField, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldEncode(v *HandoverCancelAcknowledgeIEFieldValueCodec) *func(HandoverCancelAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecFieldPath(v *HandoverCancelAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeIEFieldValueCodec, a0 HandoverCancelAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeIEFieldValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeIEFieldValueCodec, a0 HandoverCancelAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeIETableMethodInfoCriticalityDiagnostics(v HandoverCancelAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeHandoverCancelAcknowledgeIETableMethodInfoENBUES1APID(v HandoverCancelAcknowledgeIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverCancelAcknowledgeIETableMethodInfoMMEUES1APID(v HandoverCancelAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeIEValueFieldId(v *HandoverCancelAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverCancelAcknowledgeIEValueFieldIsOpaque(v *HandoverCancelAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverCancelAcknowledgeIEValueFieldOpaque(v *HandoverCancelAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverCancelAcknowledgeIEValueFieldReceived(v *HandoverCancelAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEValueFieldReplay(v *HandoverCancelAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *HandoverCancelAcknowledgeIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeHandoverCancelAcknowledgeIEValueFieldRowENBUES1APID(v *HandoverCancelAcknowledgeIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverCancelAcknowledgeIEValueFieldRowMMEUES1APID(v *HandoverCancelAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverCancelAcknowledgeIEValueMethodCaptureSemantics(v HandoverCancelAcknowledgeIEValue, a0 aper.SemanticCapture) HandoverCancelAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodCompareSemantics(v HandoverCancelAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodDecode(v HandoverCancelAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverCancelAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodEncode(v HandoverCancelAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverCancelAcknowledgeIEValueMethodEncodeFresh(v HandoverCancelAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodMatchesID(v HandoverCancelAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodReason(v HandoverCancelAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodRule(v HandoverCancelAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 HandoverCancelAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelAcknowledgeMMEUES1APIDIEBindingFieldCodec(v *HandoverCancelAcknowledgeMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCancelAcknowledgeMMEUES1APIDIEBindingFieldGet(v *HandoverCancelAcknowledgeMMEUES1APIDIEBinding) *func(*HandoverCancelAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCancelAcknowledgeMMEUES1APIDIEBindingFieldInfo(v *HandoverCancelAcknowledgeMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelAcknowledgeMMEUES1APIDIEBindingFieldInject(v *HandoverCancelAcknowledgeMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverCancelAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverFailureCauseIEBindingFieldCodec(v *HandoverFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeHandoverFailureCauseIEBindingFieldGet(v *HandoverFailureCauseIEBinding) *func(*HandoverFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeHandoverFailureCauseIEBindingFieldInfo(v *HandoverFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverFailureCauseIEBindingFieldInject(v *HandoverFailureCauseIEBinding) *func(s14.Cause) HandoverFailureIEValue {
	return &v.inject
}
func BridgeHandoverFailureCriticalityDiagnosticsIEBindingFieldCodec(v *HandoverFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeHandoverFailureCriticalityDiagnosticsIEBindingFieldGet(v *HandoverFailureCriticalityDiagnosticsIEBinding) *func(*HandoverFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeHandoverFailureCriticalityDiagnosticsIEBindingFieldInfo(v *HandoverFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverFailureCriticalityDiagnosticsIEBindingFieldInject(v *HandoverFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) HandoverFailureIEValue {
	return &v.inject
}
func BridgeHandoverFailureIEContainerAPERValueFieldContext(v *HandoverFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEContainerAPERValueFieldReceived(v *HandoverFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEContainerAPERValueFieldReplay(v *HandoverFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEContainerAPERValueFieldWithoutReplay(v *HandoverFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEContainerValueCodecFieldCapture(v *HandoverFailureIEContainerValueCodec) *func(HandoverFailureIEContainer, aper.DecodeState) (HandoverFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureIEContainerValueCodecFieldCompare(v *HandoverFailureIEContainerValueCodec) *func(HandoverFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureIEContainerValueCodecFieldContext(v *HandoverFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEContainerValueCodecFieldDecode(v *HandoverFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverFailureIEContainer, error) {
	return &v.decode
}
func BridgeHandoverFailureIEContainerValueCodecFieldEncode(v *HandoverFailureIEContainerValueCodec) *func(HandoverFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureIEContainerValueCodecFieldPath(v *HandoverFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureIEContainerValueCodecMethodEncodeBudgetValue(v HandoverFailureIEContainerValueCodec, a0 HandoverFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureIEContainerValueCodecMethodEncodeChanged(v HandoverFailureIEContainerValueCodec, a0 HandoverFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureIEFieldAPERValueFieldContext(v *HandoverFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEFieldAPERValueFieldReceived(v *HandoverFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEFieldAPERValueFieldReplay(v *HandoverFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEFieldAPERValueFieldWithoutReplay(v *HandoverFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEFieldFieldReceived(v *HandoverFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverFailureIEFieldFieldReplay(v *HandoverFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEFieldFieldStream(v *HandoverFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverFailureIEFieldFieldWithoutReplay(v *HandoverFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEFieldMethodMarshalAPERTo(v *HandoverFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverFailureIEFieldMethodUnmarshalAPERFrom(v *HandoverFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverFailureIEFieldValueCodecFieldCapture(v *HandoverFailureIEFieldValueCodec) *func(HandoverFailureIEField, aper.DecodeState) (HandoverFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureIEFieldValueCodecFieldCompare(v *HandoverFailureIEFieldValueCodec) *func(HandoverFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureIEFieldValueCodecFieldContext(v *HandoverFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEFieldValueCodecFieldDecode(v *HandoverFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverFailureIEField, error) {
	return &v.decode
}
func BridgeHandoverFailureIEFieldValueCodecFieldEncode(v *HandoverFailureIEFieldValueCodec) *func(HandoverFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureIEFieldValueCodecFieldPath(v *HandoverFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureIEFieldValueCodecMethodEncodeBudgetValue(v HandoverFailureIEFieldValueCodec, a0 HandoverFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureIEFieldValueCodecMethodEncodeChanged(v HandoverFailureIEFieldValueCodec, a0 HandoverFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureIETableMethodInfoCause(v HandoverFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeHandoverFailureIETableMethodInfoCriticalityDiagnostics(v HandoverFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeHandoverFailureIETableMethodInfoMMEUES1APID(v HandoverFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverFailureIEValueERABIEContainerListAPERValueFieldContext(v *HandoverFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverFailureIEValueERABIEContainerListValueCodec) *func(HandoverFailureIEValueERABIEContainerList, aper.DecodeState) (HandoverFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverFailureIEValueERABIEContainerListValueCodec) *func(HandoverFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldContext(v *HandoverFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverFailureIEValueERABIEContainerListValueCodec) *func(HandoverFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecFieldPath(v *HandoverFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverFailureIEValueERABIEContainerListValueCodec, a0 HandoverFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverFailureIEValueERABIEContainerListValueCodec, a0 HandoverFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureIEValueFieldId(v *HandoverFailureIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverFailureIEValueFieldIsOpaque(v *HandoverFailureIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverFailureIEValueFieldOpaque(v *HandoverFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverFailureIEValueFieldReceived(v *HandoverFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEValueFieldReplay(v *HandoverFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEValueFieldRowCause(v *HandoverFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeHandoverFailureIEValueFieldRowCriticalityDiagnostics(v *HandoverFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeHandoverFailureIEValueFieldRowMMEUES1APID(v *HandoverFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverFailureIEValueMethodCaptureSemantics(v HandoverFailureIEValue, a0 aper.SemanticCapture) HandoverFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverFailureIEValueMethodCompareSemantics(v HandoverFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverFailureIEValueMethodDecode(v HandoverFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverFailureIEValueMethodEncode(v HandoverFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverFailureIEValueMethodEncodeFresh(v HandoverFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverFailureIEValueMethodMatchesID(v HandoverFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverFailureIEValueMethodReason(v HandoverFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverFailureIEValueMethodRule(v HandoverFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverFailureIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverFailureIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolIEContainerList, aper.DecodeState) (HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverFailureIEValueProtocolIEContainerListValueCodec, a0 HandoverFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverFailureIEValueProtocolIEContainerListValueCodec, a0 HandoverFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverFailureMMEUES1APIDIEBindingFieldCodec(v *HandoverFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverFailureMMEUES1APIDIEBindingFieldGet(v *HandoverFailureMMEUES1APIDIEBinding) *func(*HandoverFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverFailureMMEUES1APIDIEBindingFieldInfo(v *HandoverFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverFailureMMEUES1APIDIEBindingFieldInject(v *HandoverFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverFailureIEValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureCauseIEBindingFieldCodec(v *HandoverPreparationFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeHandoverPreparationFailureCauseIEBindingFieldGet(v *HandoverPreparationFailureCauseIEBinding) *func(*HandoverPreparationFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeHandoverPreparationFailureCauseIEBindingFieldInfo(v *HandoverPreparationFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureCauseIEBindingFieldInject(v *HandoverPreparationFailureCauseIEBinding) *func(s14.Cause) HandoverPreparationFailureIEValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *HandoverPreparationFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeHandoverPreparationFailureCriticalityDiagnosticsIEBindingFieldGet(v *HandoverPreparationFailureCriticalityDiagnosticsIEBinding) *func(*HandoverPreparationFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeHandoverPreparationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *HandoverPreparationFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureCriticalityDiagnosticsIEBindingFieldInject(v *HandoverPreparationFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) HandoverPreparationFailureIEValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureENBUES1APIDIEBindingFieldCodec(v *HandoverPreparationFailureENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverPreparationFailureENBUES1APIDIEBindingFieldGet(v *HandoverPreparationFailureENBUES1APIDIEBinding) *func(*HandoverPreparationFailureIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverPreparationFailureENBUES1APIDIEBindingFieldInfo(v *HandoverPreparationFailureENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureENBUES1APIDIEBindingFieldInject(v *HandoverPreparationFailureENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverPreparationFailureIEValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureIEContainerAPERValueFieldContext(v *HandoverPreparationFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEContainerAPERValueFieldReceived(v *HandoverPreparationFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEContainerAPERValueFieldReplay(v *HandoverPreparationFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEContainerAPERValueFieldWithoutReplay(v *HandoverPreparationFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldCapture(v *HandoverPreparationFailureIEContainerValueCodec) *func(HandoverPreparationFailureIEContainer, aper.DecodeState) (HandoverPreparationFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldCompare(v *HandoverPreparationFailureIEContainerValueCodec) *func(HandoverPreparationFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldContext(v *HandoverPreparationFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldDecode(v *HandoverPreparationFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailureIEContainer, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldEncode(v *HandoverPreparationFailureIEContainerValueCodec) *func(HandoverPreparationFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureIEContainerValueCodecFieldPath(v *HandoverPreparationFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureIEContainerValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureIEContainerValueCodec, a0 HandoverPreparationFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureIEContainerValueCodecMethodEncodeChanged(v HandoverPreparationFailureIEContainerValueCodec, a0 HandoverPreparationFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureIEFieldAPERValueFieldContext(v *HandoverPreparationFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEFieldAPERValueFieldReceived(v *HandoverPreparationFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEFieldAPERValueFieldReplay(v *HandoverPreparationFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEFieldAPERValueFieldWithoutReplay(v *HandoverPreparationFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEFieldFieldReceived(v *HandoverPreparationFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverPreparationFailureIEFieldFieldReplay(v *HandoverPreparationFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEFieldFieldStream(v *HandoverPreparationFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverPreparationFailureIEFieldFieldWithoutReplay(v *HandoverPreparationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(v *HandoverPreparationFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverPreparationFailureIEFieldMethodUnmarshalAPERFrom(v *HandoverPreparationFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldCapture(v *HandoverPreparationFailureIEFieldValueCodec) *func(HandoverPreparationFailureIEField, aper.DecodeState) (HandoverPreparationFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldCompare(v *HandoverPreparationFailureIEFieldValueCodec) *func(HandoverPreparationFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldContext(v *HandoverPreparationFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldDecode(v *HandoverPreparationFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailureIEField, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldEncode(v *HandoverPreparationFailureIEFieldValueCodec) *func(HandoverPreparationFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureIEFieldValueCodecFieldPath(v *HandoverPreparationFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureIEFieldValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureIEFieldValueCodec, a0 HandoverPreparationFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureIEFieldValueCodecMethodEncodeChanged(v HandoverPreparationFailureIEFieldValueCodec, a0 HandoverPreparationFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureIETableMethodInfoCause(v HandoverPreparationFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeHandoverPreparationFailureIETableMethodInfoCriticalityDiagnostics(v HandoverPreparationFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeHandoverPreparationFailureIETableMethodInfoENBUES1APID(v HandoverPreparationFailureIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverPreparationFailureIETableMethodInfoMMEUES1APID(v HandoverPreparationFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListAPERValueFieldContext(v *HandoverPreparationFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverPreparationFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverPreparationFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverPreparationFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueERABIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldContext(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecFieldPath(v *HandoverPreparationFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureIEValueERABIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverPreparationFailureIEValueERABIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureIEValueFieldId(v *HandoverPreparationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverPreparationFailureIEValueFieldIsOpaque(v *HandoverPreparationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverPreparationFailureIEValueFieldOpaque(v *HandoverPreparationFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverPreparationFailureIEValueFieldReceived(v *HandoverPreparationFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEValueFieldReplay(v *HandoverPreparationFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEValueFieldRowCause(v *HandoverPreparationFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeHandoverPreparationFailureIEValueFieldRowCriticalityDiagnostics(v *HandoverPreparationFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeHandoverPreparationFailureIEValueFieldRowENBUES1APID(v *HandoverPreparationFailureIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverPreparationFailureIEValueFieldRowMMEUES1APID(v *HandoverPreparationFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverPreparationFailureIEValueMethodCaptureSemantics(v HandoverPreparationFailureIEValue, a0 aper.SemanticCapture) HandoverPreparationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverPreparationFailureIEValueMethodCompareSemantics(v HandoverPreparationFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverPreparationFailureIEValueMethodDecode(v HandoverPreparationFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverPreparationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverPreparationFailureIEValueMethodEncode(v HandoverPreparationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverPreparationFailureIEValueMethodEncodeFresh(v HandoverPreparationFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverPreparationFailureIEValueMethodMatchesID(v HandoverPreparationFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverPreparationFailureIEValueMethodReason(v HandoverPreparationFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverPreparationFailureIEValueMethodRule(v HandoverPreparationFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolIEContainerList, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverPreparationFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *func(HandoverPreparationFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverPreparationFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec, a0 HandoverPreparationFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverPreparationFailureMMEUES1APIDIEBindingFieldCodec(v *HandoverPreparationFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverPreparationFailureMMEUES1APIDIEBindingFieldGet(v *HandoverPreparationFailureMMEUES1APIDIEBinding) *func(*HandoverPreparationFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverPreparationFailureMMEUES1APIDIEBindingFieldInfo(v *HandoverPreparationFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureMMEUES1APIDIEBindingFieldInject(v *HandoverPreparationFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverPreparationFailureIEValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureCauseIEBindingFieldCodec(v *InitialContextSetupFailureCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupFailureCauseIEBindingFieldGet(v *InitialContextSetupFailureCauseIEBinding) *func(*InitialContextSetupFailureIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeInitialContextSetupFailureCauseIEBindingFieldInfo(v *InitialContextSetupFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureCauseIEBindingFieldInject(v *InitialContextSetupFailureCauseIEBinding) *func(s14.Cause) InitialContextSetupFailureIEValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureCriticalityDiagnosticsIEBindingFieldCodec(v *InitialContextSetupFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupFailureCriticalityDiagnosticsIEBindingFieldGet(v *InitialContextSetupFailureCriticalityDiagnosticsIEBinding) *func(*InitialContextSetupFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeInitialContextSetupFailureCriticalityDiagnosticsIEBindingFieldInfo(v *InitialContextSetupFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureCriticalityDiagnosticsIEBindingFieldInject(v *InitialContextSetupFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) InitialContextSetupFailureIEValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureENBUES1APIDIEBindingFieldCodec(v *InitialContextSetupFailureENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupFailureENBUES1APIDIEBindingFieldGet(v *InitialContextSetupFailureENBUES1APIDIEBinding) *func(*InitialContextSetupFailureIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeInitialContextSetupFailureENBUES1APIDIEBindingFieldInfo(v *InitialContextSetupFailureENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureENBUES1APIDIEBindingFieldInject(v *InitialContextSetupFailureENBUES1APIDIEBinding) *func(s00.ENBUES1APID) InitialContextSetupFailureIEValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureIEContainerAPERValueFieldContext(v *InitialContextSetupFailureIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEContainerAPERValueFieldReceived(v *InitialContextSetupFailureIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEContainerAPERValueFieldReplay(v *InitialContextSetupFailureIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEContainerAPERValueFieldWithoutReplay(v *InitialContextSetupFailureIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldCapture(v *InitialContextSetupFailureIEContainerValueCodec) *func(InitialContextSetupFailureIEContainer, aper.DecodeState) (InitialContextSetupFailureIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldCompare(v *InitialContextSetupFailureIEContainerValueCodec) *func(InitialContextSetupFailureIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldContext(v *InitialContextSetupFailureIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldDecode(v *InitialContextSetupFailureIEContainerValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailureIEContainer, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldEncode(v *InitialContextSetupFailureIEContainerValueCodec) *func(InitialContextSetupFailureIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureIEContainerValueCodecFieldPath(v *InitialContextSetupFailureIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureIEContainerValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureIEContainerValueCodec, a0 InitialContextSetupFailureIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureIEContainerValueCodecMethodEncodeChanged(v InitialContextSetupFailureIEContainerValueCodec, a0 InitialContextSetupFailureIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureIEFieldAPERValueFieldContext(v *InitialContextSetupFailureIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEFieldAPERValueFieldReceived(v *InitialContextSetupFailureIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEFieldAPERValueFieldReplay(v *InitialContextSetupFailureIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEFieldAPERValueFieldWithoutReplay(v *InitialContextSetupFailureIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEFieldFieldReceived(v *InitialContextSetupFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeInitialContextSetupFailureIEFieldFieldReplay(v *InitialContextSetupFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEFieldFieldStream(v *InitialContextSetupFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialContextSetupFailureIEFieldFieldWithoutReplay(v *InitialContextSetupFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(v *InitialContextSetupFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialContextSetupFailureIEFieldMethodUnmarshalAPERFrom(v *InitialContextSetupFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldCapture(v *InitialContextSetupFailureIEFieldValueCodec) *func(InitialContextSetupFailureIEField, aper.DecodeState) (InitialContextSetupFailureIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldCompare(v *InitialContextSetupFailureIEFieldValueCodec) *func(InitialContextSetupFailureIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldContext(v *InitialContextSetupFailureIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldDecode(v *InitialContextSetupFailureIEFieldValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailureIEField, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldEncode(v *InitialContextSetupFailureIEFieldValueCodec) *func(InitialContextSetupFailureIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureIEFieldValueCodecFieldPath(v *InitialContextSetupFailureIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureIEFieldValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureIEFieldValueCodec, a0 InitialContextSetupFailureIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureIEFieldValueCodecMethodEncodeChanged(v InitialContextSetupFailureIEFieldValueCodec, a0 InitialContextSetupFailureIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureIETableMethodInfoCause(v InitialContextSetupFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeInitialContextSetupFailureIETableMethodInfoCriticalityDiagnostics(v InitialContextSetupFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeInitialContextSetupFailureIETableMethodInfoENBUES1APID(v InitialContextSetupFailureIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeInitialContextSetupFailureIETableMethodInfoMMEUES1APID(v InitialContextSetupFailureIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListAPERValueFieldContext(v *InitialContextSetupFailureIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListAPERValueFieldReceived(v *InitialContextSetupFailureIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListAPERValueFieldReplay(v *InitialContextSetupFailureIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupFailureIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCapture(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldCompare(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldContext(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldDecode(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldEncode(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecFieldPath(v *InitialContextSetupFailureIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureIEValueERABIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureIEValueERABIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupFailureIEValueERABIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureIEValueFieldId(v *InitialContextSetupFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInitialContextSetupFailureIEValueFieldIsOpaque(v *InitialContextSetupFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeInitialContextSetupFailureIEValueFieldOpaque(v *InitialContextSetupFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInitialContextSetupFailureIEValueFieldReceived(v *InitialContextSetupFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEValueFieldReplay(v *InitialContextSetupFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEValueFieldRowCause(v *InitialContextSetupFailureIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeInitialContextSetupFailureIEValueFieldRowCriticalityDiagnostics(v *InitialContextSetupFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeInitialContextSetupFailureIEValueFieldRowENBUES1APID(v *InitialContextSetupFailureIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeInitialContextSetupFailureIEValueFieldRowMMEUES1APID(v *InitialContextSetupFailureIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeInitialContextSetupFailureIEValueMethodCaptureSemantics(v InitialContextSetupFailureIEValue, a0 aper.SemanticCapture) InitialContextSetupFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeInitialContextSetupFailureIEValueMethodCompareSemantics(v InitialContextSetupFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitialContextSetupFailureIEValueMethodDecode(v InitialContextSetupFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InitialContextSetupFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInitialContextSetupFailureIEValueMethodEncode(v InitialContextSetupFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInitialContextSetupFailureIEValueMethodEncodeFresh(v InitialContextSetupFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInitialContextSetupFailureIEValueMethodMatchesID(v InitialContextSetupFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeInitialContextSetupFailureIEValueMethodReason(v InitialContextSetupFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInitialContextSetupFailureIEValueMethodRule(v InitialContextSetupFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListAPERValueFieldContext(v *InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListAPERValueFieldReceived(v *InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListAPERValueFieldReplay(v *InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolIEContainerList, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupFailureIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec, a0 InitialContextSetupFailureIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupFailureMMEUES1APIDIEBindingFieldCodec(v *InitialContextSetupFailureMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupFailureMMEUES1APIDIEBindingFieldGet(v *InitialContextSetupFailureMMEUES1APIDIEBinding) *func(*InitialContextSetupFailureIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeInitialContextSetupFailureMMEUES1APIDIEBindingFieldInfo(v *InitialContextSetupFailureMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureMMEUES1APIDIEBindingFieldInject(v *InitialContextSetupFailureMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) InitialContextSetupFailureIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *func(*MMEConfigurationUpdateAcknowledgeIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) MMEConfigurationUpdateAcknowledgeIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEContainer, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeIEContainerValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEContainerValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeIEContainerValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldStream(v *MMEConfigurationUpdateAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(v *MMEConfigurationUpdateAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *MMEConfigurationUpdateAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEField, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEField, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeIEFieldValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeIEFieldValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAcknowledgeIETableMethodInfoCriticalityDiagnostics(v MMEConfigurationUpdateAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldId(v *MMEConfigurationUpdateAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(v *MMEConfigurationUpdateAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldOpaque(v *MMEConfigurationUpdateAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *MMEConfigurationUpdateAcknowledgeIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v MMEConfigurationUpdateAcknowledgeIEValue, a0 aper.SemanticCapture) MMEConfigurationUpdateAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v MMEConfigurationUpdateAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodDecode(v MMEConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEConfigurationUpdateAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodEncode(v MMEConfigurationUpdateAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodEncodeFresh(v MMEConfigurationUpdateAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodMatchesID(v MMEConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodReason(v MMEConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodRule(v MMEConfigurationUpdateAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
