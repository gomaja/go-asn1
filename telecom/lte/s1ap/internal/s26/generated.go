// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s26 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s26

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverPreparationFailureIEContainer is ProtocolIE-Container {{HandoverPreparationFailureIEs}} of TS 36.413: a list of HandoverPreparationFailureIEField values.
type HandoverPreparationFailureIEContainer []HandoverPreparationFailureIEField

// HandoverPreparationFailureIEField is ProtocolIE-Field {{HandoverPreparationFailureIEs}} of TS 36.413: an information element field.
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
	var zero HandoverPreparationFailureIEValue

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

// HandoverFailureIEContainer is ProtocolIE-Container {{HandoverFailureIEs}} of TS 36.413: a list of HandoverFailureIEField values.
type HandoverFailureIEContainer []HandoverFailureIEField

// HandoverFailureIEField is ProtocolIE-Field {{HandoverFailureIEs}} of TS 36.413: an information element field.
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
	var zero HandoverFailureIEValue

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

// HandoverCancelAcknowledgeIEContainer is ProtocolIE-Container {{HandoverCancelAcknowledgeIEs}} of TS 36.413: a list of HandoverCancelAcknowledgeIEField values.
type HandoverCancelAcknowledgeIEContainer []HandoverCancelAcknowledgeIEField

// HandoverCancelAcknowledgeIEField is ProtocolIE-Field {{HandoverCancelAcknowledgeIEs}} of TS 36.413: an information element field.
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
	var zero HandoverCancelAcknowledgeIEValue

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

// InitialContextSetupFailureIEContainer is ProtocolIE-Container {{InitialContextSetupFailureIEs}} of TS 36.413: a list of InitialContextSetupFailureIEField values.
type InitialContextSetupFailureIEContainer []InitialContextSetupFailureIEField

// InitialContextSetupFailureIEField is ProtocolIE-Field {{InitialContextSetupFailureIEs}} of TS 36.413: an information element field.
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
	var zero InitialContextSetupFailureIEValue

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

// ENBConfigurationUpdateAcknowledgeIEContainer is ProtocolIE-Container {{ENBConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of ENBConfigurationUpdateAcknowledgeIEField values.
type ENBConfigurationUpdateAcknowledgeIEContainer []ENBConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateAcknowledgeIEField is ProtocolIE-Field {{ENBConfigurationUpdateAcknowledgeIEs}} of TS 36.413: an information element field.
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
	var zero ENBConfigurationUpdateAcknowledgeIEValue

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

// ENBConfigurationUpdateFailureIEContainer is ProtocolIE-Container {{ENBConfigurationUpdateFailureIEs}} of TS 36.413: a list of ENBConfigurationUpdateFailureIEField values.
type ENBConfigurationUpdateFailureIEContainer []ENBConfigurationUpdateFailureIEField

// ENBConfigurationUpdateFailureIEField is ProtocolIE-Field {{ENBConfigurationUpdateFailureIEs}} of TS 36.413: an information element field.
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
	var zero ENBConfigurationUpdateFailureIEValue

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

// MMEConfigurationUpdateAcknowledgeIEContainer is ProtocolIE-Container {{MMEConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of MMEConfigurationUpdateAcknowledgeIEField values.
type MMEConfigurationUpdateAcknowledgeIEContainer []MMEConfigurationUpdateAcknowledgeIEField

// MMEConfigurationUpdateAcknowledgeIEField is ProtocolIE-Field {{MMEConfigurationUpdateAcknowledgeIEs}} of TS 36.413: an information element field.
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
	var zero MMEConfigurationUpdateAcknowledgeIEValue

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

// MMEConfigurationUpdateFailureIEField is ProtocolIE-Field {{MMEConfigurationUpdateFailureIEs}} of TS 36.413: an information element field.
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
	var zero MMEConfigurationUpdateFailureIEValue

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

// ENBConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the ENBConfigurationUpdateAcknowledgeIEs object set of TS 36.413.
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

// ENBConfigurationUpdateFailureCauseIEBinding binds Cause to the ENBConfigurationUpdateFailureIEs object set of TS 36.413.
type ENBConfigurationUpdateFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) ENBConfigurationUpdateFailureIEValue

	get func(*ENBConfigurationUpdateFailureIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateFailureCauseIEBinding) New(value s17.Cause,

) (ENBConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateFailureCauseIEBinding) Get(field *ENBConfigurationUpdateFailureIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateFailureTimeToWaitIEBinding binds TimeToWait to the ENBConfigurationUpdateFailureIEs object set of TS 36.413.
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

// ENBConfigurationUpdateFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the ENBConfigurationUpdateFailureIEs object set of TS 36.413.
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

// HandoverCancelAcknowledgeMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverCancelAcknowledgeIEs object set of TS 36.413.
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

// HandoverCancelAcknowledgeENBUES1APIDIEBinding binds ENBUES1APID to the HandoverCancelAcknowledgeIEs object set of TS 36.413.
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

// HandoverCancelAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the HandoverCancelAcknowledgeIEs object set of TS 36.413.
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

// HandoverFailureMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverFailureIEs object set of TS 36.413.
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

// HandoverFailureCauseIEBinding binds Cause to the HandoverFailureIEs object set of TS 36.413.
type HandoverFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) HandoverFailureIEValue

	get func(*HandoverFailureIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverFailureCauseIEBinding) New(value s17.Cause,

) (HandoverFailureIEField, error) {
	if b.inject == nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverFailureCauseIEBinding) Get(field *HandoverFailureIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the HandoverFailureIEs object set of TS 36.413.
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

// HandoverPreparationFailureMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverPreparationFailureIEs object set of TS 36.413.
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

// HandoverPreparationFailureENBUES1APIDIEBinding binds ENBUES1APID to the HandoverPreparationFailureIEs object set of TS 36.413.
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

// HandoverPreparationFailureCauseIEBinding binds Cause to the HandoverPreparationFailureIEs object set of TS 36.413.
type HandoverPreparationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) HandoverPreparationFailureIEValue

	get func(*HandoverPreparationFailureIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverPreparationFailureCauseIEBinding) New(value s17.Cause,

) (HandoverPreparationFailureIEField, error) {
	if b.inject == nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverPreparationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverPreparationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverPreparationFailureCauseIEBinding) Get(field *HandoverPreparationFailureIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverPreparationFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the HandoverPreparationFailureIEs object set of TS 36.413.
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

// InitialContextSetupFailureMMEUES1APIDIEBinding binds MMEUES1APID to the InitialContextSetupFailureIEs object set of TS 36.413.
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

// InitialContextSetupFailureENBUES1APIDIEBinding binds ENBUES1APID to the InitialContextSetupFailureIEs object set of TS 36.413.
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

// InitialContextSetupFailureCauseIEBinding binds Cause to the InitialContextSetupFailureIEs object set of TS 36.413.
type InitialContextSetupFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) InitialContextSetupFailureIEValue

	get func(*InitialContextSetupFailureIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialContextSetupFailureCauseIEBinding) New(value s17.Cause,

) (InitialContextSetupFailureIEField, error) {
	if b.inject == nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupFailureCauseIEBinding) Get(field *InitialContextSetupFailureIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the InitialContextSetupFailureIEs object set of TS 36.413.
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

// MMEConfigurationUpdateAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the MMEConfigurationUpdateAcknowledgeIEs object set of TS 36.413.
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

// MMEConfigurationUpdateFailureCauseIEBinding binds Cause to the MMEConfigurationUpdateFailureIEs object set of TS 36.413.
type MMEConfigurationUpdateFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) MMEConfigurationUpdateFailureIEValue

	get func(*MMEConfigurationUpdateFailureIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateFailureCauseIEBinding) New(value s17.Cause,

) (MMEConfigurationUpdateFailureIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateFailureCauseIEBinding) Get(field *MMEConfigurationUpdateFailureIEField) (*s17.Cause,

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

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList].
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

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailureIEValueERABIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBConfigurationUpdateFailureIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateFailureIEValueERABIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverCancelAcknowledgeIEValueERABIEContainerList].
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

// HandoverCancelAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type HandoverCancelAcknowledgeIEValueERABIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverFailureIEValueERABIEContainerList].
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

// HandoverFailureIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverFailureIEs}} of TS 36.413: a list of information element fields.
type HandoverFailureIEValueERABIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverPreparationFailureIEValueERABIEContainerList].
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

// HandoverPreparationFailureIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverPreparationFailureIEs}} of TS 36.413: a list of information element fields.
type HandoverPreparationFailureIEValueERABIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueERABIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupFailureIEValueERABIEContainerList].
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

// InitialContextSetupFailureIEValueERABIEContainerList is E-RAB-IE-ContainerList {{InitialContextSetupFailureIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupFailureIEValueERABIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledgeIEField].
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

// ENBConfigurationUpdateFailureIEFieldValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailureIEField].
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

// HandoverCancelAcknowledgeIEFieldValueCodec is the concrete ValueCodec[HandoverCancelAcknowledgeIEField].
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

// HandoverFailureIEFieldValueCodec is the concrete ValueCodec[HandoverFailureIEField].
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

// HandoverPreparationFailureIEFieldValueCodec is the concrete ValueCodec[HandoverPreparationFailureIEField].
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

// InitialContextSetupFailureIEFieldValueCodec is the concrete ValueCodec[InitialContextSetupFailureIEField].
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

// MMEConfigurationUpdateAcknowledgeIEFieldValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledgeIEField].
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

// ENBConfigurationUpdateAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledgeIEContainer].
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

// ENBConfigurationUpdateFailureIEContainerValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailureIEContainer].
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

// HandoverCancelAcknowledgeIEContainerValueCodec is the concrete ValueCodec[HandoverCancelAcknowledgeIEContainer].
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

// HandoverFailureIEContainerValueCodec is the concrete ValueCodec[HandoverFailureIEContainer].
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

// HandoverPreparationFailureIEContainerValueCodec is the concrete ValueCodec[HandoverPreparationFailureIEContainer].
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

// InitialContextSetupFailureIEContainerValueCodec is the concrete ValueCodec[InitialContextSetupFailureIEContainer].
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

// MMEConfigurationUpdateAcknowledgeIEContainerValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledgeIEContainer].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBConfigurationUpdateFailureIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList].
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

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverCancelAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverFailureIEValueProtocolErrorIEContainerList].
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

// HandoverFailureIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverFailureIEs}} of TS 36.413: a list of information element fields.
type HandoverFailureIEValueProtocolErrorIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverPreparationFailureIEValueProtocolErrorIEContainerList].
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

// HandoverPreparationFailureIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverPreparationFailureIEs}} of TS 36.413: a list of information element fields.
type HandoverPreparationFailureIEValueProtocolErrorIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupFailureIEValueProtocolErrorIEContainerList].
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

// InitialContextSetupFailureIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{InitialContextSetupFailureIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupFailureIEValueProtocolErrorIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList []ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailureIEValueProtocolIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateFailureIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBConfigurationUpdateFailureIEValueProtocolIEContainerList []ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverCancelAcknowledgeIEValueProtocolIEContainerList].
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

// HandoverCancelAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverCancelAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverCancelAcknowledgeIEValueProtocolIEContainerList []HandoverCancelAcknowledgeIEValueProtocolIESingleContainer

// HandoverFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverFailureIEValueProtocolIEContainerList].
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

// HandoverFailureIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverFailureIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverFailureIEValueProtocolIEContainerList []HandoverFailureIEValueProtocolIESingleContainer

// HandoverPreparationFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverPreparationFailureIEValueProtocolIEContainerList].
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

// HandoverPreparationFailureIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverPreparationFailureIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverPreparationFailureIEValueProtocolIEContainerList []HandoverPreparationFailureIEValueProtocolIESingleContainer

// InitialContextSetupFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupFailureIEValueProtocolIEContainerList].
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

// InitialContextSetupFailureIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupFailureIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type InitialContextSetupFailureIEValueProtocolIEContainerList []InitialContextSetupFailureIEValueProtocolIESingleContainer

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList []MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a single information element field.
type ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer = ENBConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateFailureIEValueERABIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBConfigurationUpdateFailureIEs}} of TS 36.413: a single information element field.
type ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer = ENBConfigurationUpdateFailureIEField

// HandoverCancelAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverCancelAcknowledgeIEValueERABIEContainerList].
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

// HandoverCancelAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverCancelAcknowledgeIEs}} of TS 36.413: a single information element field.
type HandoverCancelAcknowledgeIEValueProtocolIESingleContainer = HandoverCancelAcknowledgeIEField

// HandoverFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverFailureIEValueERABIEContainerList].
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

// HandoverFailureIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverFailureIEs}} of TS 36.413: a single information element field.
type HandoverFailureIEValueProtocolIESingleContainer = HandoverFailureIEField

// HandoverPreparationFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverPreparationFailureIEValueERABIEContainerList].
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

// HandoverPreparationFailureIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverPreparationFailureIEs}} of TS 36.413: a single information element field.
type HandoverPreparationFailureIEValueProtocolIESingleContainer = HandoverPreparationFailureIEField

// InitialContextSetupFailureIEValueERABIEContainerListAPERValue is the concrete APERValue[InitialContextSetupFailureIEValueERABIEContainerList].
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

// InitialContextSetupFailureIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{InitialContextSetupFailureIEs}} of TS 36.413: a single information element field.
type InitialContextSetupFailureIEValueProtocolIESingleContainer = InitialContextSetupFailureIEField

// MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEConfigurationUpdateAcknowledgeIEs}} of TS 36.413: a single information element field.
type MMEConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer = MMEConfigurationUpdateAcknowledgeIEField

// ENBConfigurationUpdateAcknowledgeIEFieldAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledgeIEField].
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

// ENBConfigurationUpdateFailureIEFieldAPERValue is the concrete APERValue[ENBConfigurationUpdateFailureIEField].
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

// HandoverCancelAcknowledgeIEFieldAPERValue is the concrete APERValue[HandoverCancelAcknowledgeIEField].
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

// HandoverFailureIEFieldAPERValue is the concrete APERValue[HandoverFailureIEField].
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

// HandoverPreparationFailureIEFieldAPERValue is the concrete APERValue[HandoverPreparationFailureIEField].
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

// InitialContextSetupFailureIEFieldAPERValue is the concrete APERValue[InitialContextSetupFailureIEField].
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

// MMEConfigurationUpdateAcknowledgeIEFieldAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledgeIEField].
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

// ENBConfigurationUpdateAcknowledgeIEContainerAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledgeIEContainer].
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

// ENBConfigurationUpdateFailureIEContainerAPERValue is the concrete APERValue[ENBConfigurationUpdateFailureIEContainer].
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

// HandoverCancelAcknowledgeIEContainerAPERValue is the concrete APERValue[HandoverCancelAcknowledgeIEContainer].
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

// HandoverFailureIEContainerAPERValue is the concrete APERValue[HandoverFailureIEContainer].
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

// HandoverPreparationFailureIEContainerAPERValue is the concrete APERValue[HandoverPreparationFailureIEContainer].
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

// InitialContextSetupFailureIEContainerAPERValue is the concrete APERValue[InitialContextSetupFailureIEContainer].
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

// MMEConfigurationUpdateAcknowledgeIEContainerAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledgeIEContainer].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList].
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

// HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerList].
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

// HandoverFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverFailureIEValueProtocolErrorIEContainerList].
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

// HandoverPreparationFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverPreparationFailureIEValueProtocolErrorIEContainerList].
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

// InitialContextSetupFailureIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[InitialContextSetupFailureIEValueProtocolErrorIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList].
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

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList].
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

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateFailureIEValueProtocolIEContainerList].
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

// HandoverCancelAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverCancelAcknowledgeIEValueProtocolIEContainerList].
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

// HandoverFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverFailureIEValueProtocolIEContainerList].
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

// HandoverPreparationFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverPreparationFailureIEValueProtocolIEContainerList].
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

// InitialContextSetupFailureIEValueProtocolIEContainerListAPERValue is the concrete APERValue[InitialContextSetupFailureIEValueProtocolIEContainerList].
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

// MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList].
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
func BridgeCaptureS1APCellActivationRequest(v *CellActivationRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellsToActivateList(&v.CellsToActivateList, s)
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
func BridgeCompareS1APCellsToActivateList(v *s17.CellsToActivateList, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCellsToActivateListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCompletedCellinEAI(v *s20.CompletedCellinEAI, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCompletedCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCompletedCellinTAI(v *s20.CompletedCellinTAI, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCompletedCellinTAIItem(&(*v)[i], s)
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
	s25.BridgeCaptureS1APCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
			s03.BridgeCompareS1APProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			s08.BridgeCompareS1APTriggeringMessage(v.TriggeringMessage, s)
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
	s15.BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnosticsIEList(v *s17.CriticalityDiagnosticsIEList, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCriticalityDiagnosticsIEItem(&(*v)[i], s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s17.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s08.BridgeCompareS1APTimeToWait(v.rowTimeToWait, s)
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
	s25.BridgeCaptureS1APCompletedCellinEAI(&v.CompletedCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s15.BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
func (v MMEConfigurationUpdateFailureIEValue) captureSemantics(s aper.SemanticCapture) MMEConfigurationUpdateFailureIEValue {
	BridgeCaptureS1APMMEConfigurationUpdateFailureIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEConfigurationUpdateFailureIEValue(v *MMEConfigurationUpdateFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(65):
			{
				f := s.Begin()
				s.Bool(v.rowTimeToWait == nil)
				if v.rowTimeToWait != nil {
					s08.BridgeCompareS1APTimeToWait(v.rowTimeToWait, s)
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
func (v MMEConfigurationUpdateFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEConfigurationUpdateFailureIEValue(&v, &s)
	return s
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
	IEsCriticalityDiagnostics      s17.CriticalityDiagnosticsIEList             `asn1:"tag:3,context,implicit,optional" json:"IEsCriticalityDiagnostics,omitzero"`
	iEsCriticalityDiagnosticsIndef bool                                         `asn1:"-" json:"-"`
	IEExtensions                   s09.CriticalityDiagnosticsExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	CompletedCellinEAI      s20.CompletedCellinEAI                             `asn1:"tag:1,context,implicit"`
	completedCellinEAIIndef bool                                               `asn1:"-" json:"-"`
	IEExtensions            s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                               `asn1:"-" json:"-"`
	extCount                int64                                              `asn1:"-" json:"-"`
	extPresent              []bool                                             `asn1:"-" json:"-"`
	extData                 [][]byte                                           `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
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
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ProcedureCode), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
				if err := s17.BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CriticalityDiagnostics from APER format.
func (v *CriticalityDiagnostics) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CriticalityDiagnostics) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	bb.EnterComponent("CriticalityDiagnostics")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnostics")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	v.perPadding = padding
	return nil
}
func (v *CriticalityDiagnostics) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnostics{}
	var extAdditions aper.ExtensionAdditions
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
		val_procedurecode, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
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
		tmp_iescriticalitydiagnostics := make(s17.CriticalityDiagnosticsIEList, 0)
		_, errCollection_iescriticalitydiagnostics := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(^uint(0)>>1) || fragmentOffset_iescriticalitydiagnostics > int64(^uint(0)>>1)-fragmentLength_iescriticalitydiagnostics {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_iescriticalitydiagnostics; i++ {
				var elem s17.CriticalityDiagnosticsIEItem
				elementMark := bb.EnterIndex(fragmentOffset_iescriticalitydiagnostics + i)
				if err := s17.BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CriticalityDiagnosticsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CriticalityDiagnosticsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
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
		bb.LeaveComponent(toleranceMark_ieextensions)
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
			if err := s20.BridgeCompletedCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes EmergencyAreaIDBroadcastItem from APER format.
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	bb.EnterComponent("EmergencyAreaIDBroadcastItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDBroadcastItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItem")
	}
	v.perPadding = padding
	return nil
}
func (v *EmergencyAreaIDBroadcastItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDBroadcastItem{}
	var extAdditions aper.ExtensionAdditions
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
	v.CompletedCellinEAI = make(s20.CompletedCellinEAI, 0)
	_, errCollection_completedcellineai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_completedcellineai, fragmentLength_completedcellineai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_completedcellineai < 0 || fragmentLength_completedcellineai < 0 || fragmentLength_completedcellineai > int64(^uint(0)>>1) || fragmentOffset_completedcellineai > int64(^uint(0)>>1)-fragmentLength_completedcellineai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_completedcellineai; i++ {
			var elem s20.CompletedCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_completedcellineai + i)
			if err := s20.BridgeCompletedCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.EmergencyAreaIDBroadcastItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
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
		bb.LeaveComponent(toleranceMark_ieextensions)
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
func (v *CriticalityDiagnostics) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnostics", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDBroadcastItem", v.receivedLocation, v.perPadding)
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

// CellActivationRequest represents the ASN.1 type CellActivationRequest (SEQUENCE).
type CellActivationRequest struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	CellsToActivateList      s17.CellsToActivateList `asn1:"tag:0,context,implicit"`
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
	if err := aper.EncodeBoolean(bb, v.MinimumActivationTime != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CellsToActivateList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellstoactivatelist < 0 || fragmentOffset_cellstoactivatelist > int64(len(v.CellsToActivateList)) || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(len(v.CellsToActivateList[fragmentOffset_cellstoactivatelist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellsToActivateList[fragmentOffset_cellstoactivatelist : fragmentOffset_cellstoactivatelist+fragmentLength_cellstoactivatelist] {
			if err := s17.BridgeCellsToActivateListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellsToActivateList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellsToActivateList: %w", err)
	}
	if v.MinimumActivationTime != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MinimumActivationTime), s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(60), false); err != nil {
			return fmt.Errorf("encoding minimumActivationTime: %w", err)
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

// UnmarshalAPER decodes CellActivationRequest from APER format.
func (v *CellActivationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellActivationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	bb.EnterComponent("CellActivationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellActivationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *CellActivationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellActivationRequest{}
	var extAdditions aper.ExtensionAdditions
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
	v.CellsToActivateList = make(s17.CellsToActivateList, 0)
	_, errCollection_cellstoactivatelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(^uint(0)>>1) || fragmentOffset_cellstoactivatelist > int64(^uint(0)>>1)-fragmentLength_cellstoactivatelist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellstoactivatelist; i++ {
			var elem s17.CellsToActivateListItem
			elementMark := bb.EnterIndex(fragmentOffset_cellstoactivatelist + i)
			if err := s17.BridgeCellsToActivateListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		val_minimumactivationtime, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(60), false)
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
func (v *CellActivationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellActivationRequest", v.receivedLocation, v.perPadding)
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
	rowCause                  *s17.Cause
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
func (v *ENBConfigurationUpdateFailureIEValue) AsCause() (*s17.Cause, bool) {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
	rowCause                  *s17.Cause
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
func (v *HandoverFailureIEValue) AsCause() (*s17.Cause, bool) {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
	rowCause                  *s17.Cause
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
func (v *HandoverPreparationFailureIEValue) AsCause() (*s17.Cause, bool) {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
	rowCause                  *s17.Cause
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
func (v *InitialContextSetupFailureIEValue) AsCause() (*s17.Cause, bool) {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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

type MMEConfigurationUpdateFailureIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s17.Cause
	rowTimeToWait             *s00.TimeToWait
	rowCriticalityDiagnostics *CriticalityDiagnostics
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

// Opaque returns the retained opaque open value of MMEConfigurationUpdateFailureIEValue and reports whether the opaque alternative is selected.
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

// AsCause returns the selected Cause value of MMEConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateFailureIEValue) AsCause() (*s17.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsTimeToWait returns the selected TimeToWait value of MMEConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateFailureIEValue) AsTimeToWait() (*s00.TimeToWait, bool) {
	if v == nil || v.id != s00.ProtocolIEID(65) || v.rowTimeToWait == nil {
		return nil, false
	}
	return v.rowTimeToWait, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of MMEConfigurationUpdateFailureIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEConfigurationUpdateFailureIEValue:", v.id)
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ENBConfigurationUpdateAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
	return ENBConfigurationUpdateFailureCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding ENBConfigurationUpdateFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s17.Cause) ENBConfigurationUpdateFailureIEValue {
			return ENBConfigurationUpdateFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *ENBConfigurationUpdateFailureIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
			raw.BudgetBuffer().EnterComponent("TimeToWait")
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(65), raw)
			if err != nil {
				var empty s00.TimeToWait
				return empty, runtime.WrapDecodePath(err, "TimeToWait")
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
			s08.BridgeCompareS1APTimeToWait(&v, &s)
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ENBConfigurationUpdateFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
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
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero HandoverCancelAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
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
	return HandoverFailureCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding HandoverFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s17.Cause) HandoverFailureIEValue {
			return HandoverFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverFailureIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero HandoverFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
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
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
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
	return HandoverPreparationFailureCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding HandoverPreparationFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s17.Cause) HandoverPreparationFailureIEValue {
			return HandoverPreparationFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverPreparationFailureIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero HandoverPreparationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
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
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
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
	return InitialContextSetupFailureCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding InitialContextSetupFailureIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s17.Cause) InitialContextSetupFailureIEValue {
			return InitialContextSetupFailureIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *InitialContextSetupFailureIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero InitialContextSetupFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero MMEConfigurationUpdateAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
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
func BridgeCellActivationRequestMethodMarshalAPERTo(v *CellActivationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellActivationRequestMethodUnmarshalAPERFrom(v *CellActivationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsFieldExtCount(v *CriticalityDiagnostics) *int64   { return &v.extCount }
func BridgeCriticalityDiagnosticsFieldExtData(v *CriticalityDiagnostics) *[][]byte { return &v.extData }
func BridgeCriticalityDiagnosticsFieldExtPresent(v *CriticalityDiagnostics) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsFieldPerPadding(v *CriticalityDiagnostics) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsFieldReceived(v *CriticalityDiagnostics) *bool { return &v.received }
func BridgeCriticalityDiagnosticsFieldReceivedBytes(v *CriticalityDiagnostics) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsFieldReceivedLocation(v *CriticalityDiagnostics) *aper.Location {
	return &v.receivedLocation
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(v *CriticalityDiagnostics, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v *ENBConfigurationUpdateAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldId(v *ENBConfigurationUpdateAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(v *ENBConfigurationUpdateAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueFieldOpaque(v *ENBConfigurationUpdateAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodMatchesID(v ENBConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueMethodRule(v ENBConfigurationUpdateAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v *ENBConfigurationUpdateFailureIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeENBConfigurationUpdateFailureIEValueFieldId(v *ENBConfigurationUpdateFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateFailureIEValueFieldIsOpaque(v *ENBConfigurationUpdateFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateFailureIEValueFieldOpaque(v *ENBConfigurationUpdateFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationUpdateFailureIEValueFieldRowCause(v *ENBConfigurationUpdateFailureIEValue) **s17.Cause {
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
func BridgeENBConfigurationUpdateFailureIEValueMethodMatchesID(v ENBConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationUpdateFailureIEValueMethodRule(v ENBConfigurationUpdateFailureIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERTo(v *EmergencyAreaIDBroadcastItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERFrom(v *EmergencyAreaIDBroadcastItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeHandoverCancelAcknowledgeIEFieldFieldReplay(v *HandoverCancelAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeHandoverCancelAcknowledgeIEValueFieldId(v *HandoverCancelAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverCancelAcknowledgeIEValueFieldIsOpaque(v *HandoverCancelAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverCancelAcknowledgeIEValueFieldOpaque(v *HandoverCancelAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeHandoverCancelAcknowledgeIEValueMethodMatchesID(v HandoverCancelAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverCancelAcknowledgeIEValueMethodRule(v HandoverCancelAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeHandoverFailureIEFieldFieldReplay(v *HandoverFailureIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeHandoverFailureIEValueFieldId(v *HandoverFailureIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverFailureIEValueFieldIsOpaque(v *HandoverFailureIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverFailureIEValueFieldOpaque(v *HandoverFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverFailureIEValueFieldRowCause(v *HandoverFailureIEValue) **s17.Cause {
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
func BridgeHandoverFailureIEValueMethodMatchesID(v HandoverFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverFailureIEValueMethodRule(v HandoverFailureIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeHandoverPreparationFailureIEFieldFieldReplay(v *HandoverPreparationFailureIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeHandoverPreparationFailureIEValueFieldId(v *HandoverPreparationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverPreparationFailureIEValueFieldIsOpaque(v *HandoverPreparationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverPreparationFailureIEValueFieldOpaque(v *HandoverPreparationFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverPreparationFailureIEValueFieldRowCause(v *HandoverPreparationFailureIEValue) **s17.Cause {
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
func BridgeHandoverPreparationFailureIEValueMethodMatchesID(v HandoverPreparationFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverPreparationFailureIEValueMethodRule(v HandoverPreparationFailureIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeInitialContextSetupFailureIEFieldFieldReplay(v *InitialContextSetupFailureIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeInitialContextSetupFailureIEValueFieldId(v *InitialContextSetupFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInitialContextSetupFailureIEValueFieldIsOpaque(v *InitialContextSetupFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeInitialContextSetupFailureIEValueFieldOpaque(v *InitialContextSetupFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInitialContextSetupFailureIEValueFieldRowCause(v *InitialContextSetupFailureIEValue) **s17.Cause {
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
func BridgeInitialContextSetupFailureIEValueMethodMatchesID(v InitialContextSetupFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeInitialContextSetupFailureIEValueMethodRule(v InitialContextSetupFailureIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeMMEConfigurationUpdateAcknowledgeIEFieldFieldReplay(v *MMEConfigurationUpdateAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldId(v *MMEConfigurationUpdateAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(v *MMEConfigurationUpdateAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldOpaque(v *MMEConfigurationUpdateAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodMatchesID(v MMEConfigurationUpdateAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEConfigurationUpdateAcknowledgeIEValueMethodRule(v MMEConfigurationUpdateAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldCodec(v *MMEConfigurationUpdateFailureCauseIEBinding) *s17.CauseValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldGet(v *MMEConfigurationUpdateFailureCauseIEBinding) *func(*MMEConfigurationUpdateFailureIEValue) (*s17.Cause, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldInfo(v *MMEConfigurationUpdateFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureCauseIEBindingFieldInject(v *MMEConfigurationUpdateFailureCauseIEBinding) *func(s17.Cause) MMEConfigurationUpdateFailureIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureIEFieldFieldReplay(v *MMEConfigurationUpdateFailureIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeMMEConfigurationUpdateFailureIEValueFieldId(v *MMEConfigurationUpdateFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldIsOpaque(v *MMEConfigurationUpdateFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldOpaque(v *MMEConfigurationUpdateFailureIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldRowCause(v *MMEConfigurationUpdateFailureIEValue) **s17.Cause {
	return &v.rowCause
}
func BridgeMMEConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(v *MMEConfigurationUpdateFailureIEValue) **CriticalityDiagnostics {
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
func BridgeMMEConfigurationUpdateFailureIEValueMethodEncodeFresh(v MMEConfigurationUpdateFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodMatchesID(v MMEConfigurationUpdateFailureIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEConfigurationUpdateFailureIEValueMethodRule(v MMEConfigurationUpdateFailureIEValue) aper.SourceRule {
	return v.rule()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBConfigurationUpdateAcknowledgeIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBConfigurationUpdateFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 65:
		if value, ok := v.AsTimeToWait(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverCancelAcknowledgeIEValue) Selected() (any, bool) {
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
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *HandoverFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if value, ok := v.AsMMEUES1APID(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverPreparationFailureIEValue) Selected() (any, bool) {
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
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *InitialContextSetupFailureIEValue) Selected() (any, bool) {
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
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MMEConfigurationUpdateAcknowledgeIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MMEConfigurationUpdateFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 65:
		if value, ok := v.AsTimeToWait(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
