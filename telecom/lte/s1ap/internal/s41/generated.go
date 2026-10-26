// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s41 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s41

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UplinkNASTransportIEContainer is ProtocolIE-Container {{UplinkNASTransport-IEs}} of TS 36.413: a list of UplinkNASTransportIEField values.
type UplinkNASTransportIEContainer []UplinkNASTransportIEField

// UplinkNASTransportIEField is ProtocolIE-Field {{UplinkNASTransport-IEs}} of TS 36.413: an information element field.
type UplinkNASTransportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UplinkNASTransportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEField) WithoutReplay() UplinkNASTransportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UplinkNASTransportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UplinkNASTransportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UplinkNASTransportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkNASTransportIEField{}
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
	var zero UplinkNASTransportIEValue

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

// WriteReplaceWarningResponseIEContainer is ProtocolIE-Container {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of WriteReplaceWarningResponseIEField values.
type WriteReplaceWarningResponseIEContainer []WriteReplaceWarningResponseIEField

// WriteReplaceWarningResponseIEField is ProtocolIE-Field {{WriteReplaceWarningResponseIEs}} of TS 36.413: an information element field.
type WriteReplaceWarningResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         WriteReplaceWarningResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEField) WithoutReplay() WriteReplaceWarningResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *WriteReplaceWarningResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *WriteReplaceWarningResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *WriteReplaceWarningResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningResponseIEField{}
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
	var zero WriteReplaceWarningResponseIEValue

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

// KillRequestIEContainer is ProtocolIE-Container {{KillRequestIEs}} of TS 36.413: a list of KillRequestIEField values.
type KillRequestIEContainer []KillRequestIEField

// KillRequestIEField is ProtocolIE-Field {{KillRequestIEs}} of TS 36.413: an information element field.
type KillRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         KillRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEField) WithoutReplay() KillRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *KillRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *KillRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *KillRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillRequestIEField{}
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
	var zero KillRequestIEValue

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

// KillResponseIEContainer is ProtocolIE-Container {{KillResponseIEs}} of TS 36.413: a list of KillResponseIEField values.
type KillResponseIEContainer []KillResponseIEField

// KillResponseIEField is ProtocolIE-Field {{KillResponseIEs}} of TS 36.413: an information element field.
type KillResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         KillResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEField) WithoutReplay() KillResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *KillResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *KillResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *KillResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillResponseIEField{}
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
	var zero KillResponseIEValue

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

// TAIValueCodec is the concrete ValueCodec[TAI].
type TAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s40.TAI,

		error)
	encode func(s40.TAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s40.TAI, aper.DecodeState,

	) (s40.TAI, aper.Snapshot,

	)
	compare func(s40.TAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIValueCodec) New(value s40.TAI,

) (TAIAPERValue, error) {
	if c.encode == nil {
		return TAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIValueCodec) EncodeAPER(value TAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIValueCodec) encodeBudgetValue(value s40.TAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIValueCodec) encodeChanged(value s40.TAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseMessageIdentifierIEBinding binds MessageIdentifier to the KillResponseIEs object set of TS 36.413.
type KillResponseMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseMessageIdentifierIEBinding) Get(field *KillResponseIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillResponseSerialNumberIEBinding binds SerialNumber to the KillResponseIEs object set of TS 36.413.
type KillResponseSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseSerialNumberIEBinding) Codec() s02.SerialNumberValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b KillResponseSerialNumberIEBinding) New(value s00.SerialNumber,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseSerialNumberIEBinding) Get(field *KillResponseIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillResponseBroadcastCancelledAreaListIEBinding binds BroadcastCancelledAreaList to the KillResponseIEs object set of TS 36.413.
type KillResponseBroadcastCancelledAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  BroadcastCancelledAreaListValueCodec
	inject func(BroadcastCancelledAreaList,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*BroadcastCancelledAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Codec() BroadcastCancelledAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseBroadcastCancelledAreaListIEBinding) New(value BroadcastCancelledAreaList,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Get(field *KillResponseIEField) (*BroadcastCancelledAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BroadcastCancelledAreaListValueCodec is the concrete ValueCodec[BroadcastCancelledAreaList].
type BroadcastCancelledAreaListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BroadcastCancelledAreaList,

		error)
	encode func(BroadcastCancelledAreaList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BroadcastCancelledAreaList, aper.DecodeState,

	) (BroadcastCancelledAreaList, aper.Snapshot,

	)
	compare func(BroadcastCancelledAreaList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BroadcastCancelledAreaListValueCodec) New(value BroadcastCancelledAreaList,

) (BroadcastCancelledAreaListAPERValue, error) {
	if c.encode == nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BroadcastCancelledAreaListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BroadcastCancelledAreaListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BroadcastCancelledAreaListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BroadcastCancelledAreaListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BroadcastCancelledAreaListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BroadcastCancelledAreaListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BroadcastCancelledAreaListValueCodec) EncodeAPER(value BroadcastCancelledAreaListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BroadcastCancelledAreaListValueCodec) encodeBudgetValue(value BroadcastCancelledAreaList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BroadcastCancelledAreaListValueCodec) encodeChanged(value BroadcastCancelledAreaList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the KillResponseIEs object set of TS 36.413.
type KillResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Get(field *KillResponseIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportTAIIEBinding binds TAI to the LocationReportIEs object set of TS 36.413.
type LocationReportTAIIEBinding struct {
	info   s00.FieldInfo
	codec  TAIValueCodec
	inject func(s40.TAI,

	) s40.LocationReportIEValue

	get func(*s40.LocationReportIEValue,

	) (*s40.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportTAIIEBinding) Codec() TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportTAIIEBinding) New(value s40.TAI,

) (s40.LocationReportIEField, error) {
	if b.inject == nil {
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s40.LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s40.LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return s40.LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportTAIIEBinding) Get(field *s40.LocationReportIEField) (*s40.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TAIListForRestartValueCodec is the concrete ValueCodec[TAIListForRestart].
type TAIListForRestartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIListForRestart,

		error)
	encode func(TAIListForRestart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIListForRestart, aper.DecodeState,

	) (TAIListForRestart, aper.Snapshot,

	)
	compare func(TAIListForRestart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIListForRestartValueCodec) New(value TAIListForRestart,

) (TAIListForRestartAPERValue, error) {
	if c.encode == nil {
		return TAIListForRestartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIListForRestartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIListForRestartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIListForRestartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIListForRestartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIListForRestartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIListForRestartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIListForRestartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIListForRestartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIListForRestartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIListForRestartValueCodec) EncodeAPER(value TAIListForRestartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIListForRestartValueCodec) encodeBudgetValue(value TAIListForRestart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIListForRestartValueCodec) encodeChanged(value TAIListForRestart,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportMMEUES1APIDIEBinding binds MMEUES1APID to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportMMEUES1APIDIEBinding) Get(field *UplinkNASTransportIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportENBUES1APIDIEBinding binds ENBUES1APID to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportENBUES1APIDIEBinding) Get(field *UplinkNASTransportIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportNASPDUIEBinding binds NASPDU to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportNASPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASPDUValueCodec
	inject func(s00.NASPDU,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s00.NASPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportNASPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportNASPDUIEBinding) Codec() s01.NASPDUValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportNASPDUIEBinding) New(value s00.NASPDU,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportNASPDUIEBinding) Get(field *UplinkNASTransportIEField) (*s00.NASPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportEUTRANCGIIEBinding binds EUTRANCGI to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s20.EUTRANCGIValueCodec
	inject func(s20.EUTRANCGI,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s20.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportEUTRANCGIIEBinding) Codec() s20.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportEUTRANCGIIEBinding) New(value s20.EUTRANCGI,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportEUTRANCGIIEBinding) Get(field *UplinkNASTransportIEField) (*s20.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportTAIIEBinding binds TAI to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportTAIIEBinding struct {
	info   s00.FieldInfo
	codec  TAIValueCodec
	inject func(s40.TAI,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s40.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportTAIIEBinding) Codec() TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportTAIIEBinding) New(value s40.TAI,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportTAIIEBinding) Get(field *UplinkNASTransportIEField) (*s40.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportTransportLayerAddressIEBinding binds TransportLayerAddress to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportTransportLayerAddressIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TransportLayerAddressValueCodec
	inject func(s00.TransportLayerAddress,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s00.TransportLayerAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportTransportLayerAddressIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportTransportLayerAddressIEBinding) Codec() s02.TransportLayerAddressValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportTransportLayerAddressIEBinding) New(value s00.TransportLayerAddress,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportTransportLayerAddressIEBinding) Get(field *UplinkNASTransportIEField) (*s00.TransportLayerAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportLHNIDIEBinding binds LHNID to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportLHNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LHNIDValueCodec
	inject func(s00.LHNID,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s00.LHNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportLHNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportLHNIDIEBinding) Codec() s01.LHNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportLHNIDIEBinding) New(value s00.LHNID,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLHNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportLHNIDIEBinding) Get(field *UplinkNASTransportIEField) (*s00.LHNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportPSCellInformationIEBinding binds PSCellInformation to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportPSCellInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s23.PSCellInformationValueCodec
	inject func(s23.PSCellInformation,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s23.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportPSCellInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportPSCellInformationIEBinding) Codec() s23.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportPSCellInformationIEBinding) New(value s23.PSCellInformation,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportPSCellInformationIEBinding) Get(field *UplinkNASTransportIEField) (*s23.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkNASTransportLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the UplinkNASTransport-IEs object set of TS 36.413.
type UplinkNASTransportLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s22.LTENTNTAIInformationValueCodec
	inject func(s22.LTENTNTAIInformation,

	) UplinkNASTransportIEValue

	get func(*UplinkNASTransportIEValue,

	) (*s22.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportLTENTNTAIInformationIEBinding) Codec() s22.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkNASTransportLTENTNTAIInformationIEBinding) New(value s22.LTENTNTAIInformation,

) (UplinkNASTransportIEField, error) {
	if b.inject == nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkNASTransportLTENTNTAIInformationIEBinding) Get(field *UplinkNASTransportIEField) (*s22.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseMessageIdentifierIEBinding binds MessageIdentifier to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseSerialNumberIEBinding binds SerialNumber to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Codec() s02.SerialNumberValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) New(value s00.SerialNumber,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding binds BroadcastCompletedAreaList to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  BroadcastCompletedAreaListValueCodec
	inject func(BroadcastCompletedAreaList,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*BroadcastCompletedAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Codec() BroadcastCompletedAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) New(value BroadcastCompletedAreaList,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*BroadcastCompletedAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BroadcastCompletedAreaListValueCodec is the concrete ValueCodec[BroadcastCompletedAreaList].
type BroadcastCompletedAreaListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BroadcastCompletedAreaList,

		error)
	encode func(BroadcastCompletedAreaList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BroadcastCompletedAreaList, aper.DecodeState,

	) (BroadcastCompletedAreaList, aper.Snapshot,

	)
	compare func(BroadcastCompletedAreaList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BroadcastCompletedAreaListValueCodec) New(value BroadcastCompletedAreaList,

) (BroadcastCompletedAreaListAPERValue, error) {
	if c.encode == nil {
		return BroadcastCompletedAreaListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BroadcastCompletedAreaListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BroadcastCompletedAreaListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BroadcastCompletedAreaListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BroadcastCompletedAreaListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BroadcastCompletedAreaListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BroadcastCompletedAreaListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BroadcastCompletedAreaListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BroadcastCompletedAreaListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BroadcastCompletedAreaListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BroadcastCompletedAreaListValueCodec) EncodeAPER(value BroadcastCompletedAreaListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BroadcastCompletedAreaListValueCodec) encodeBudgetValue(value BroadcastCompletedAreaList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BroadcastCompletedAreaListValueCodec) encodeChanged(value BroadcastCompletedAreaList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AreaScopeOfMDTValueCodec is the concrete ValueCodec[AreaScopeOfMDT].
type AreaScopeOfMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AreaScopeOfMDT,

		error)
	encode func(AreaScopeOfMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AreaScopeOfMDT, aper.DecodeState,

	) (AreaScopeOfMDT, aper.Snapshot,

	)
	compare func(AreaScopeOfMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AreaScopeOfMDTValueCodec) New(value AreaScopeOfMDT,

) (AreaScopeOfMDTAPERValue, error) {
	if c.encode == nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AreaScopeOfMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AreaScopeOfMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AreaScopeOfMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AreaScopeOfMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AreaScopeOfMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AreaScopeOfMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AreaScopeOfMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AreaScopeOfMDTValueCodec) EncodeAPER(value AreaScopeOfMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AreaScopeOfMDTValueCodec) encodeBudgetValue(value AreaScopeOfMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AreaScopeOfMDTValueCodec) encodeChanged(value AreaScopeOfMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AreaScopeOfQMCValueCodec is the concrete ValueCodec[AreaScopeOfQMC].
type AreaScopeOfQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AreaScopeOfQMC,

		error)
	encode func(AreaScopeOfQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AreaScopeOfQMC, aper.DecodeState,

	) (AreaScopeOfQMC, aper.Snapshot,

	)
	compare func(AreaScopeOfQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AreaScopeOfQMCValueCodec) New(value AreaScopeOfQMC,

) (AreaScopeOfQMCAPERValue, error) {
	if c.encode == nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AreaScopeOfQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AreaScopeOfQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AreaScopeOfQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AreaScopeOfQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AreaScopeOfQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AreaScopeOfQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AreaScopeOfQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AreaScopeOfQMCValueCodec) EncodeAPER(value AreaScopeOfQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AreaScopeOfQMCValueCodec) encodeBudgetValue(value AreaScopeOfQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AreaScopeOfQMCValueCodec) encodeChanged(value AreaScopeOfQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBListValueCodec is the concrete ValueCodec[RecommendedENBList].
type RecommendedENBListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s40.RecommendedENBList,

		error)
	encode func(s40.RecommendedENBList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s40.RecommendedENBList, aper.DecodeState,

	) (s40.RecommendedENBList, aper.Snapshot,

	)
	compare func(s40.RecommendedENBList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBListValueCodec) New(value s40.RecommendedENBList,

) (s40.RecommendedENBListAPERValue, error) {
	if c.encode == nil {
		return s40.RecommendedENBListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s40.RecommendedENBListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s40.RecommendedENBListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s40.RecommendedENBListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s40.RecommendedENBListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s40.RecommendedENBListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s40.RecommendedENBListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s40.RecommendedENBListAPERValue {
			sealed := s40.RecommendedENBListAPERValue{Value: value}
			*s40.BridgeRecommendedENBListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s40.BridgeRecommendedENBListAPERValueFieldReplay(&sealed) = replay
			*s40.BridgeRecommendedENBListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s40.RecommendedENBListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBListValueCodec) EncodeAPER(value s40.RecommendedENBListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s40.BridgeRecommendedENBListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s40.BridgeRecommendedENBListAPERValueFieldContext(&value) == c.context && !fresh && (*s40.BridgeRecommendedENBListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s40.BridgeRecommendedENBListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s40.BridgeRecommendedENBListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s40.BridgeRecommendedENBListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RecommendedENBListValueCodec) encodeBudgetValue(value s40.RecommendedENBList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBListValueCodec) encodeChanged(value s40.RecommendedENBList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBIDValueCodec is the concrete ValueCodec[SourceeNBID].
type SourceeNBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBID,

		error)
	encode func(SourceeNBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBID, aper.DecodeState,

	) (SourceeNBID, aper.Snapshot,

	)
	compare func(SourceeNBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBIDValueCodec) New(value SourceeNBID,

) (SourceeNBIDAPERValue, error) {
	if c.encode == nil {
		return SourceeNBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBIDValueCodec) EncodeAPER(value SourceeNBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceeNBIDValueCodec) encodeBudgetValue(value SourceeNBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBIDValueCodec) encodeChanged(value SourceeNBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedMDTValueCodec is the concrete ValueCodec[TAIBasedMDT].
type TAIBasedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedMDT,

		error)
	encode func(TAIBasedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedMDT, aper.DecodeState,

	) (TAIBasedMDT, aper.Snapshot,

	)
	compare func(TAIBasedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedMDTValueCodec) New(value TAIBasedMDT,

) (TAIBasedMDTAPERValue, error) {
	if c.encode == nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedMDTValueCodec) EncodeAPER(value TAIBasedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedMDTValueCodec) encodeBudgetValue(value TAIBasedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedMDTValueCodec) encodeChanged(value TAIBasedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedQMCValueCodec is the concrete ValueCodec[TAIBasedQMC].
type TAIBasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedQMC,

		error)
	encode func(TAIBasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedQMC, aper.DecodeState,

	) (TAIBasedQMC, aper.Snapshot,

	)
	compare func(TAIBasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedQMCValueCodec) New(value TAIBasedQMC,

) (TAIBasedQMCAPERValue, error) {
	if c.encode == nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedQMCValueCodec) EncodeAPER(value TAIBasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedQMCValueCodec) encodeBudgetValue(value TAIBasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedQMCValueCodec) encodeChanged(value TAIBasedQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBroadcastValueCodec is the concrete ValueCodec[TAIBroadcast].
type TAIBroadcastValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBroadcast,

		error)
	encode func(TAIBroadcast,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBroadcast, aper.DecodeState,

	) (TAIBroadcast, aper.Snapshot,

	)
	compare func(TAIBroadcast, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBroadcastValueCodec) New(value TAIBroadcast,

) (TAIBroadcastAPERValue, error) {
	if c.encode == nil {
		return TAIBroadcastAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBroadcastAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBroadcastAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBroadcastAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBroadcastValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBroadcastAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBroadcastAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBroadcastAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBroadcastAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBroadcastAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBroadcastValueCodec) EncodeAPER(value TAIBroadcastAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBroadcastValueCodec) encodeBudgetValue(value TAIBroadcast,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBroadcastValueCodec) encodeChanged(value TAIBroadcast,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBroadcastItemValueCodec is the concrete ValueCodec[TAIBroadcastItem].
type TAIBroadcastItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBroadcastItem,

		error)
	encode func(TAIBroadcastItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBroadcastItem, aper.DecodeState,

	) (TAIBroadcastItem, aper.Snapshot,

	)
	compare func(TAIBroadcastItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBroadcastItemValueCodec) New(value TAIBroadcastItem,

) (TAIBroadcastItemAPERValue, error) {
	if c.encode == nil {
		return TAIBroadcastItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBroadcastItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBroadcastItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBroadcastItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBroadcastItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBroadcastItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBroadcastItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBroadcastItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBroadcastItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBroadcastItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBroadcastItemValueCodec) EncodeAPER(value TAIBroadcastItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBroadcastItemValueCodec) encodeBudgetValue(value TAIBroadcastItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBroadcastItemValueCodec) encodeChanged(value TAIBroadcastItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAICancelledValueCodec is the concrete ValueCodec[TAICancelled].
type TAICancelledValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAICancelled,

		error)
	encode func(TAICancelled,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAICancelled, aper.DecodeState,

	) (TAICancelled, aper.Snapshot,

	)
	compare func(TAICancelled, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAICancelledValueCodec) New(value TAICancelled,

) (TAICancelledAPERValue, error) {
	if c.encode == nil {
		return TAICancelledAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAICancelledAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAICancelledAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAICancelledAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAICancelledValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAICancelledAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAICancelledAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAICancelledAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAICancelledAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAICancelledAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAICancelledValueCodec) EncodeAPER(value TAICancelledAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAICancelledValueCodec) encodeBudgetValue(value TAICancelled,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAICancelledValueCodec) encodeChanged(value TAICancelled,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAICancelledItemValueCodec is the concrete ValueCodec[TAICancelledItem].
type TAICancelledItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAICancelledItem,

		error)
	encode func(TAICancelledItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAICancelledItem, aper.DecodeState,

	) (TAICancelledItem, aper.Snapshot,

	)
	compare func(TAICancelledItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAICancelledItemValueCodec) New(value TAICancelledItem,

) (TAICancelledItemAPERValue, error) {
	if c.encode == nil {
		return TAICancelledItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAICancelledItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAICancelledItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAICancelledItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAICancelledItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAICancelledItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAICancelledItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAICancelledItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAICancelledItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAICancelledItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAICancelledItemValueCodec) EncodeAPER(value TAICancelledItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAICancelledItemValueCodec) encodeBudgetValue(value TAICancelledItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAICancelledItemValueCodec) encodeChanged(value TAICancelledItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIListforMDTValueCodec is the concrete ValueCodec[TAIListforMDT].
type TAIListforMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIListforMDT,

		error)
	encode func(TAIListforMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIListforMDT, aper.DecodeState,

	) (TAIListforMDT, aper.Snapshot,

	)
	compare func(TAIListforMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIListforMDTValueCodec) New(value TAIListforMDT,

) (TAIListforMDTAPERValue, error) {
	if c.encode == nil {
		return TAIListforMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIListforMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIListforMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIListforMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIListforMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIListforMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIListforMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIListforMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIListforMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIListforMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIListforMDTValueCodec) EncodeAPER(value TAIListforMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIListforMDTValueCodec) encodeBudgetValue(value TAIListforMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIListforMDTValueCodec) encodeChanged(value TAIListforMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIListforQMCValueCodec is the concrete ValueCodec[TAIListforQMC].
type TAIListforQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIListforQMC,

		error)
	encode func(TAIListforQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIListforQMC, aper.DecodeState,

	) (TAIListforQMC, aper.Snapshot,

	)
	compare func(TAIListforQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIListforQMCValueCodec) New(value TAIListforQMC,

) (TAIListforQMCAPERValue, error) {
	if c.encode == nil {
		return TAIListforQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIListforQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIListforQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIListforQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIListforQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIListforQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIListforQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIListforQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIListforQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIListforQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIListforQMCValueCodec) EncodeAPER(value TAIListforQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIListforQMCValueCodec) encodeBudgetValue(value TAIListforQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIListforQMCValueCodec) encodeChanged(value TAIListforQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIListforWarningValueCodec is the concrete ValueCodec[TAIListforWarning].
type TAIListforWarningValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIListforWarning,

		error)
	encode func(TAIListforWarning,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIListforWarning, aper.DecodeState,

	) (TAIListforWarning, aper.Snapshot,

	)
	compare func(TAIListforWarning, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIListforWarningValueCodec) New(value TAIListforWarning,

) (TAIListforWarningAPERValue, error) {
	if c.encode == nil {
		return TAIListforWarningAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIListforWarningAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIListforWarningAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIListforWarningAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIListforWarningValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIListforWarningAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIListforWarningAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIListforWarningAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIListforWarningAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIListforWarningAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIListforWarningValueCodec) EncodeAPER(value TAIListforWarningAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIListforWarningValueCodec) encodeBudgetValue(value TAIListforWarning,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIListforWarningValueCodec) encodeChanged(value TAIListforWarning,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TAI-ExtIEs}} codec of TS 36.413.
func TAIExtIEsValueExtensionTableCodec(table s00.TAIExtIEsValueExtensionTable, bounds aper.ListBounds) s13.TAIExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s13.TAIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.TAIExtIEsExtContainerValueCodec {
		sealed := s13.TAIExtIEsExtContainerValueCodec{}
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldPath(&sealed) = "TAIExtIEsExtContainer"
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.TAIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.TAIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.TAIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "TAIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TAIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TAIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.TAIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.TAIExtIEsExtContainer, options aper.DecodeState) (s13.TAIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeTAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.TAIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeTAIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeTAIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TAIAPERValue is the concrete APERValue[TAI].
type TAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s40.TAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIAPERValue) WithoutReplay() TAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BroadcastCancelledAreaListAPERValue is the concrete APERValue[BroadcastCancelledAreaList].
type BroadcastCancelledAreaListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BroadcastCancelledAreaList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BroadcastCancelledAreaListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BroadcastCancelledAreaListAPERValue) WithoutReplay() BroadcastCancelledAreaListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIListForRestartAPERValue is the concrete APERValue[TAIListForRestart].
type TAIListForRestartAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIListForRestart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIListForRestartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIListForRestartAPERValue) WithoutReplay() TAIListForRestartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BroadcastCompletedAreaListAPERValue is the concrete APERValue[BroadcastCompletedAreaList].
type BroadcastCompletedAreaListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BroadcastCompletedAreaList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BroadcastCompletedAreaListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BroadcastCompletedAreaListAPERValue) WithoutReplay() BroadcastCompletedAreaListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AreaScopeOfMDTAPERValue is the concrete APERValue[AreaScopeOfMDT].
type AreaScopeOfMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   AreaScopeOfMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AreaScopeOfMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AreaScopeOfMDTAPERValue) WithoutReplay() AreaScopeOfMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AreaScopeOfQMCAPERValue is the concrete APERValue[AreaScopeOfQMC].
type AreaScopeOfQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   AreaScopeOfQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AreaScopeOfQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AreaScopeOfQMCAPERValue) WithoutReplay() AreaScopeOfQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBIDAPERValue is the concrete APERValue[SourceeNBID].
type SourceeNBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceeNBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBIDAPERValue) WithoutReplay() SourceeNBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedMDTAPERValue is the concrete APERValue[TAIBasedMDT].
type TAIBasedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBasedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTAPERValue) WithoutReplay() TAIBasedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedQMCAPERValue is the concrete APERValue[TAIBasedQMC].
type TAIBasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCAPERValue) WithoutReplay() TAIBasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBroadcastAPERValue is the concrete APERValue[TAIBroadcast].
type TAIBroadcastAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBroadcast

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBroadcastAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastAPERValue) WithoutReplay() TAIBroadcastAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBroadcastItemAPERValue is the concrete APERValue[TAIBroadcastItem].
type TAIBroadcastItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBroadcastItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBroadcastItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBroadcastItemAPERValue) WithoutReplay() TAIBroadcastItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAICancelledAPERValue is the concrete APERValue[TAICancelled].
type TAICancelledAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAICancelled

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAICancelledAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledAPERValue) WithoutReplay() TAICancelledAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAICancelledItemAPERValue is the concrete APERValue[TAICancelledItem].
type TAICancelledItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAICancelledItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAICancelledItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAICancelledItemAPERValue) WithoutReplay() TAICancelledItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIListforMDTAPERValue is the concrete APERValue[TAIListforMDT].
type TAIListforMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIListforMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIListforMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIListforMDTAPERValue) WithoutReplay() TAIListforMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIListforQMCAPERValue is the concrete APERValue[TAIListforQMC].
type TAIListforQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIListforQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIListforQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIListforQMCAPERValue) WithoutReplay() TAIListforQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIListforWarningAPERValue is the concrete APERValue[TAIListforWarning].
type TAIListforWarningAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIListforWarning

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIListforWarningAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIListforWarningAPERValue) WithoutReplay() TAIListforWarningAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{KillRequestIEs}} of TS 36.413: a list of information element fields.
type KillRequestIEValueERABIEContainerList []KillRequestIEValueProtocolIESingleContainer

// KillResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueERABIEContainerList].
type KillResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueERABIEContainerList, error)
	encode  func(KillResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueERABIEContainerList, aper.DecodeState) (KillResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueERABIEContainerListValueCodec) New(value KillResponseIEValueERABIEContainerList) (KillResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueERABIEContainerListValueCodec) encodeChanged(value KillResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{KillResponseIEs}} of TS 36.413: a list of information element fields.
type KillResponseIEValueERABIEContainerList []KillResponseIEValueProtocolIESingleContainer

// UplinkNASTransportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UplinkNASTransportIEValueERABIEContainerList].
type UplinkNASTransportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransportIEValueERABIEContainerList, error)
	encode  func(UplinkNASTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransportIEValueERABIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot)
	compare func(UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportIEValueERABIEContainerListValueCodec) New(value UplinkNASTransportIEValueERABIEContainerList) (UplinkNASTransportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportIEValueERABIEContainerListValueCodec) EncodeAPER(value UplinkNASTransportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkNASTransportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UplinkNASTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportIEValueERABIEContainerListValueCodec) encodeChanged(value UplinkNASTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UplinkNASTransport-IEs}} of TS 36.413: a list of information element fields.
type UplinkNASTransportIEValueERABIEContainerList []UplinkNASTransportIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueERABIEContainerList].
type WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueERABIEContainerList) (WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningResponseIEValueERABIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillRequestIEFieldValueCodec is the concrete ValueCodec[KillRequestIEField].
type KillRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEField, error)
	encode  func(KillRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEField, aper.DecodeState) (KillRequestIEField, aper.Snapshot)
	compare func(KillRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEFieldValueCodec) New(value KillRequestIEField) (KillRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEFieldValueCodec) EncodeAPER(value KillRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEFieldValueCodec) encodeBudgetValue(value KillRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEFieldValueCodec) encodeChanged(value KillRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEFieldValueCodec is the concrete ValueCodec[KillResponseIEField].
type KillResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEField, error)
	encode  func(KillResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEField, aper.DecodeState) (KillResponseIEField, aper.Snapshot)
	compare func(KillResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEFieldValueCodec) New(value KillResponseIEField) (KillResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEFieldValueCodec) EncodeAPER(value KillResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEFieldValueCodec) encodeBudgetValue(value KillResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEFieldValueCodec) encodeChanged(value KillResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportIEFieldValueCodec is the concrete ValueCodec[UplinkNASTransportIEField].
type UplinkNASTransportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransportIEField, error)
	encode  func(UplinkNASTransportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransportIEField, aper.DecodeState) (UplinkNASTransportIEField, aper.Snapshot)
	compare func(UplinkNASTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportIEFieldValueCodec) New(value UplinkNASTransportIEField) (UplinkNASTransportIEFieldAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportIEFieldValueCodec) EncodeAPER(value UplinkNASTransportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkNASTransportIEFieldValueCodec) encodeBudgetValue(value UplinkNASTransportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportIEFieldValueCodec) encodeChanged(value UplinkNASTransportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEFieldValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEField].
type WriteReplaceWarningResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEField, error)
	encode  func(WriteReplaceWarningResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEField, aper.DecodeState) (WriteReplaceWarningResponseIEField, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEFieldValueCodec) New(value WriteReplaceWarningResponseIEField) (WriteReplaceWarningResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEFieldValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEFieldValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEFieldValueCodec) encodeChanged(value WriteReplaceWarningResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEContainerValueCodec is the concrete ValueCodec[KillRequestIEContainer].
type KillRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEContainer, error)
	encode  func(KillRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEContainer, aper.DecodeState) (KillRequestIEContainer, aper.Snapshot)
	compare func(KillRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEContainerValueCodec) New(value KillRequestIEContainer) (KillRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEContainerValueCodec) EncodeAPER(value KillRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEContainerValueCodec) encodeBudgetValue(value KillRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEContainerValueCodec) encodeChanged(value KillRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEContainerValueCodec is the concrete ValueCodec[KillResponseIEContainer].
type KillResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEContainer, error)
	encode  func(KillResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEContainer, aper.DecodeState) (KillResponseIEContainer, aper.Snapshot)
	compare func(KillResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEContainerValueCodec) New(value KillResponseIEContainer) (KillResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEContainerValueCodec) EncodeAPER(value KillResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEContainerValueCodec) encodeBudgetValue(value KillResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEContainerValueCodec) encodeChanged(value KillResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportIEContainerValueCodec is the concrete ValueCodec[UplinkNASTransportIEContainer].
type UplinkNASTransportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransportIEContainer, error)
	encode  func(UplinkNASTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransportIEContainer, aper.DecodeState) (UplinkNASTransportIEContainer, aper.Snapshot)
	compare func(UplinkNASTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportIEContainerValueCodec) New(value UplinkNASTransportIEContainer) (UplinkNASTransportIEContainerAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportIEContainerValueCodec) EncodeAPER(value UplinkNASTransportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkNASTransportIEContainerValueCodec) encodeBudgetValue(value UplinkNASTransportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportIEContainerValueCodec) encodeChanged(value UplinkNASTransportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEContainerValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEContainer].
type WriteReplaceWarningResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, error)
	encode  func(WriteReplaceWarningResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEContainer, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEContainerValueCodec) New(value WriteReplaceWarningResponseIEContainer) (WriteReplaceWarningResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEContainerValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEContainerValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEContainerValueCodec) encodeChanged(value WriteReplaceWarningResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueProtocolErrorIEContainerList].
type KillResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(KillResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) New(value KillResponseIEValueProtocolErrorIEContainerList) (KillResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{KillResponseIEs}} of TS 36.413: a list of information element fields.
type KillResponseIEValueProtocolErrorIEContainerList []KillResponseIEValueProtocolIESingleContainer

// UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UplinkNASTransportIEValueProtocolErrorIEContainerList].
type UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransportIEValueProtocolErrorIEContainerList, error)
	encode  func(UplinkNASTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) New(value UplinkNASTransportIEValueProtocolErrorIEContainerList) (UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UplinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UplinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UplinkNASTransport-IEs}} of TS 36.413: a list of information element fields.
type UplinkNASTransportIEValueProtocolErrorIEContainerList []UplinkNASTransportIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueProtocolIEContainerList].
type KillResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, error)
	encode  func(KillResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueProtocolIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) New(value KillResponseIEValueProtocolIEContainerList) (KillResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value KillResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {KillResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type KillResponseIEValueProtocolIEContainerList []KillResponseIEValueProtocolIESingleContainer

// UplinkNASTransportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UplinkNASTransportIEValueProtocolIEContainerList].
type UplinkNASTransportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransportIEValueProtocolIEContainerList, error)
	encode  func(UplinkNASTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransportIEValueProtocolIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportIEValueProtocolIEContainerListValueCodec) New(value UplinkNASTransportIEValueProtocolIEContainerList) (UplinkNASTransportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UplinkNASTransportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkNASTransportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UplinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportIEValueProtocolIEContainerListValueCodec) encodeChanged(value UplinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UplinkNASTransport-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UplinkNASTransportIEValueProtocolIEContainerList []UplinkNASTransportIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueProtocolIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueProtocolIEContainerList) (WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type WriteReplaceWarningResponseIEValueProtocolIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[KillRequestIEValueERABIEContainerList].
type KillRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEValueERABIEContainerListAPERValue) WithoutReplay() KillRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{KillRequestIEs}} of TS 36.413: a single information element field.
type KillRequestIEValueProtocolIESingleContainer = KillRequestIEField

// KillResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueERABIEContainerList].
type KillResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueERABIEContainerListAPERValue) WithoutReplay() KillResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{KillResponseIEs}} of TS 36.413: a single information element field.
type KillResponseIEValueProtocolIESingleContainer = KillResponseIEField

// UplinkNASTransportIEValueERABIEContainerListAPERValue is the concrete APERValue[UplinkNASTransportIEValueERABIEContainerList].
type UplinkNASTransportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkNASTransportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEValueERABIEContainerListAPERValue) WithoutReplay() UplinkNASTransportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UplinkNASTransport-IEs}} of TS 36.413: a single information element field.
type UplinkNASTransportIEValueProtocolIESingleContainer = UplinkNASTransportIEField

// WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueERABIEContainerList].
type WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{WriteReplaceWarningResponseIEs}} of TS 36.413: a single information element field.
type WriteReplaceWarningResponseIEValueProtocolIESingleContainer = WriteReplaceWarningResponseIEField

// KillRequestIEFieldAPERValue is the concrete APERValue[KillRequestIEField].
type KillRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEFieldAPERValue) WithoutReplay() KillRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEFieldAPERValue is the concrete APERValue[KillResponseIEField].
type KillResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEFieldAPERValue) WithoutReplay() KillResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportIEFieldAPERValue is the concrete APERValue[UplinkNASTransportIEField].
type UplinkNASTransportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkNASTransportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEFieldAPERValue) WithoutReplay() UplinkNASTransportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEFieldAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEField].
type WriteReplaceWarningResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEFieldAPERValue) WithoutReplay() WriteReplaceWarningResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEContainerAPERValue is the concrete APERValue[KillRequestIEContainer].
type KillRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEContainerAPERValue) WithoutReplay() KillRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEContainerAPERValue is the concrete APERValue[KillResponseIEContainer].
type KillResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEContainerAPERValue) WithoutReplay() KillResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportIEContainerAPERValue is the concrete APERValue[UplinkNASTransportIEContainer].
type UplinkNASTransportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkNASTransportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEContainerAPERValue) WithoutReplay() UplinkNASTransportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEContainerAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEContainer].
type WriteReplaceWarningResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEContainerAPERValue) WithoutReplay() WriteReplaceWarningResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueProtocolErrorIEContainerList].
type KillResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() KillResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UplinkNASTransportIEValueProtocolErrorIEContainerList].
type UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkNASTransportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UplinkNASTransportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueProtocolIEContainerList].
type KillResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() KillResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UplinkNASTransportIEValueProtocolIEContainerList].
type UplinkNASTransportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkNASTransportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportIEValueProtocolIEContainerListAPERValue) WithoutReplay() UplinkNASTransportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueProtocolIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APAreaScopeOfMDT(v *AreaScopeOfMDT, s *aper.SemanticCapture) {
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s25.BridgeCaptureS1APCellBasedMDT(v.CellBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s40.BridgeCaptureS1APTABasedMDT(v.TABased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
		{
			f := s.Begin()
			s.Bool(v.PLMNWide == nil)
			if v.PLMNWide != nil {
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCaptureS1APTAIBasedMDT(v.TAIBased, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APAreaScopeOfMDT(v *AreaScopeOfMDT, s *aper.SemanticComparison) {
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s25.BridgeCompareS1APCellBasedMDT(v.CellBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s40.BridgeCompareS1APTABasedMDT(v.TABased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
		{
			f := s.Begin()
			s.Bool(v.PLMNWide == nil)
			if v.PLMNWide != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCompareS1APTAIBasedMDT(v.TAIBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APAreaScopeOfQMC(v *AreaScopeOfQMC, s *aper.SemanticCapture) {
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
	case s00.AreaScopeOfQMCChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s25.BridgeCaptureS1APCellBasedQMC(v.CellBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s40.BridgeCaptureS1APTABasedQMC(v.TABased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCaptureS1APTAIBasedQMC(v.TAIBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		{
			f := s.Begin()
			s.Bool(v.PLMNAreaBased == nil)
			if v.PLMNAreaBased != nil {
				s23.BridgeCaptureS1APPLMNAreaBasedQMC(v.PLMNAreaBased, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAreaScopeOfQMC(v *AreaScopeOfQMC, s *aper.SemanticComparison) {
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
	case s00.AreaScopeOfQMCChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s25.BridgeCompareS1APCellBasedQMC(v.CellBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s40.BridgeCompareS1APTABasedQMC(v.TABased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCompareS1APTAIBasedQMC(v.TAIBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		{
			f := s.Begin()
			s.Bool(v.PLMNAreaBased == nil)
			if v.PLMNAreaBased != nil {
				s23.BridgeCompareS1APPLMNAreaBasedQMC(v.PLMNAreaBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBroadcastCancelledAreaList(v *BroadcastCancelledAreaList, s *aper.SemanticCapture) {
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
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		s25.BridgeCaptureS1APCellIDCancelled(&v.CellIDCancelled, s)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		BridgeCaptureS1APTAICancelled(&v.TAICancelled, s)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		s25.BridgeCaptureS1APEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBroadcastCancelledAreaList(v *BroadcastCancelledAreaList, s *aper.SemanticComparison) {
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
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		s25.BridgeCompareS1APCellIDCancelled(&v.CellIDCancelled, s)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		BridgeCompareS1APTAICancelled(&v.TAICancelled, s)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		s28.BridgeCompareS1APEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBroadcastCompletedAreaList(v *BroadcastCompletedAreaList, s *aper.SemanticCapture) {
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
	case s00.BroadcastCompletedAreaListChoiceCellIDBroadcast:
		s25.BridgeCaptureS1APCellIDBroadcast(&v.CellIDBroadcast, s)
	case s00.BroadcastCompletedAreaListChoiceTAIBroadcast:
		BridgeCaptureS1APTAIBroadcast(&v.TAIBroadcast, s)
	case s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast:
		s26.BridgeCaptureS1APEmergencyAreaIDBroadcast(&v.EmergencyAreaIDBroadcast, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBroadcastCompletedAreaList(v *BroadcastCompletedAreaList, s *aper.SemanticComparison) {
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
	case s00.BroadcastCompletedAreaListChoiceCellIDBroadcast:
		s25.BridgeCompareS1APCellIDBroadcast(&v.CellIDBroadcast, s)
	case s00.BroadcastCompletedAreaListChoiceTAIBroadcast:
		BridgeCompareS1APTAIBroadcast(&v.TAIBroadcast, s)
	case s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast:
		s28.BridgeCompareS1APEmergencyAreaIDBroadcast(&v.EmergencyAreaIDBroadcast, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APKillRequestIEValue(v *KillRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s00.BridgeCaptureS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s00.BridgeCaptureS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(113):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaList == nil)
				if v.rowWarningAreaList != nil {
					BridgeCaptureS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(191):
			{
				f := s.Begin()
				s.Bool(v.rowKillAllWarningMessages == nil)
				if v.rowKillAllWarningMessages != nil {
					s00.BridgeCaptureS1APKillAllWarningMessages(v.rowKillAllWarningMessages, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillRequestIEValue) captureSemantics(s aper.SemanticCapture) KillRequestIEValue {
	BridgeCaptureS1APKillRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APKillRequestIEValue(v *KillRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s02.BridgeCompareS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s08.BridgeCompareS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(113):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaList == nil)
				if v.rowWarningAreaList != nil {
					BridgeCompareS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(191):
			{
				f := s.Begin()
				s.Bool(v.rowKillAllWarningMessages == nil)
				if v.rowKillAllWarningMessages != nil {
					s02.BridgeCompareS1APKillAllWarningMessages(v.rowKillAllWarningMessages, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APKillRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APKillResponseIEValue(v *KillResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s00.BridgeCaptureS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s00.BridgeCaptureS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(141):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCancelledAreaList == nil)
				if v.rowBroadcastCancelledAreaList != nil {
					BridgeCaptureS1APBroadcastCancelledAreaList(v.rowBroadcastCancelledAreaList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillResponseIEValue) captureSemantics(s aper.SemanticCapture) KillResponseIEValue {
	BridgeCaptureS1APKillResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APKillResponseIEValue(v *KillResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s02.BridgeCompareS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s08.BridgeCompareS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(141):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCancelledAreaList == nil)
				if v.rowBroadcastCancelledAreaList != nil {
					BridgeCompareS1APBroadcastCancelledAreaList(v.rowBroadcastCancelledAreaList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APKillResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSourceeNBID(v *SourceeNBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APGlobalENBID(&v.GlobalENBID, s)
	s40.BridgeCaptureS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s39.BridgeSourceeNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSourceeNBID(v *SourceeNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APGlobalENBID(&v.GlobalENBID, s)
	s40.BridgeCompareS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s39.BridgeSourceeNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIBasedMDT(v *TAIBasedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APTAIListforMDT(&v.TAIListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBasedMDT(v *TAIBasedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APTAIListforMDT(&v.TAIListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIBasedQMC(v *TAIBasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APTAIListforQMC(&v.TAIListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBasedQMC(v *TAIBasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APTAIListforQMC(&v.TAIListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIBroadcast(v *TAIBroadcast, s *aper.SemanticCapture) {
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
			BridgeCaptureS1APTAIBroadcastItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIBroadcast(v *TAIBroadcast, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAIBroadcastItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTAIBroadcastItem(v *TAIBroadcastItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCaptureS1APTAI(&v.TAI, s)
	s25.BridgeCaptureS1APCompletedCellinTAI(&v.CompletedCellinTAI, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBroadcastItem(v *TAIBroadcastItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCompareS1APTAI(&v.TAI, s)
	s26.BridgeCompareS1APCompletedCellinTAI(&v.CompletedCellinTAI, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAICancelled(v *TAICancelled, s *aper.SemanticCapture) {
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
			BridgeCaptureS1APTAICancelledItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAICancelled(v *TAICancelled, s *aper.SemanticComparison) {
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
			BridgeCompareS1APTAICancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTAICancelledItem(v *TAICancelledItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCaptureS1APTAI(&v.TAI, s)
	s25.BridgeCaptureS1APCancelledCellinTAI(&v.CancelledCellinTAI, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAICancelledItem(v *TAICancelledItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCompareS1APTAI(&v.TAI, s)
	s25.BridgeCompareS1APCancelledCellinTAI(&v.CancelledCellinTAI, s)
	s.Bool(v.IEExtensions == nil)
	s40.BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListForRestart(v *TAIListForRestart, s *aper.SemanticCapture) {
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
			s40.BridgeCaptureS1APTAI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIListForRestart(v *TAIListForRestart, s *aper.SemanticComparison) {
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
			s40.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTAIListforMDT(v *TAIListforMDT, s *aper.SemanticCapture) {
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
			s40.BridgeCaptureS1APTAI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIListforMDT(v *TAIListforMDT, s *aper.SemanticComparison) {
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
			s40.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTAIListforQMC(v *TAIListforQMC, s *aper.SemanticCapture) {
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
			s40.BridgeCaptureS1APTAI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIListforQMC(v *TAIListforQMC, s *aper.SemanticComparison) {
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
			s40.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTAIListforWarning(v *TAIListforWarning, s *aper.SemanticCapture) {
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
			s40.BridgeCaptureS1APTAI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIListforWarning(v *TAIListforWarning, s *aper.SemanticComparison) {
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
			s40.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APUplinkNASTransportIEValue(v *UplinkNASTransportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s00.BridgeCaptureS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s20.BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s40.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(155):
			{
				f := s.Begin()
				s.Bool(v.rowGWTransportLayerAddress == nil)
				if v.rowGWTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowGWTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(184):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOLGWTransportLayerAddress == nil)
				if v.rowSIPTOLGWTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSIPTOLGWTransportLayerAddress, s)
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
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s23.BridgeCaptureS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s22.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkNASTransportIEValue) captureSemantics(s aper.SemanticCapture) UplinkNASTransportIEValue {
	BridgeCaptureS1APUplinkNASTransportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUplinkNASTransportIEValue(v *UplinkNASTransportIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s02.BridgeCompareS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s20.BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s40.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(155):
			{
				f := s.Begin()
				s.Bool(v.rowGWTransportLayerAddress == nil)
				if v.rowGWTransportLayerAddress != nil {
					s08.BridgeCompareS1APTransportLayerAddress(v.rowGWTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(184):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOLGWTransportLayerAddress == nil)
				if v.rowSIPTOLGWTransportLayerAddress != nil {
					s08.BridgeCompareS1APTransportLayerAddress(v.rowSIPTOLGWTransportLayerAddress, s)
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
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s23.BridgeCompareS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s22.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkNASTransportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUplinkNASTransportIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APWarningAreaList(v *WarningAreaList, s *aper.SemanticCapture) {
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
	case s00.WarningAreaListChoiceCellIDList:
		s25.BridgeCaptureS1APECGIList(&v.CellIDList, s)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		BridgeCaptureS1APTAIListforWarning(&v.TrackingAreaListforWarning, s)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		s00.BridgeCaptureS1APEmergencyAreaIDList(&v.EmergencyAreaIDList, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWarningAreaList(v *WarningAreaList, s *aper.SemanticComparison) {
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
	case s00.WarningAreaListChoiceCellIDList:
		s28.BridgeCompareS1APECGIList(&v.CellIDList, s)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		BridgeCompareS1APTAIListforWarning(&v.TrackingAreaListforWarning, s)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		s02.BridgeCompareS1APEmergencyAreaIDList(&v.EmergencyAreaIDList, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWriteReplaceWarningResponseIEValue(v *WriteReplaceWarningResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s00.BridgeCaptureS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s00.BridgeCaptureS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(120):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCompletedAreaList == nil)
				if v.rowBroadcastCompletedAreaList != nil {
					BridgeCaptureS1APBroadcastCompletedAreaList(v.rowBroadcastCompletedAreaList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WriteReplaceWarningResponseIEValue) captureSemantics(s aper.SemanticCapture) WriteReplaceWarningResponseIEValue {
	BridgeCaptureS1APWriteReplaceWarningResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APWriteReplaceWarningResponseIEValue(v *WriteReplaceWarningResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s02.BridgeCompareS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s08.BridgeCompareS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(120):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCompletedAreaList == nil)
				if v.rowBroadcastCompletedAreaList != nil {
					BridgeCompareS1APBroadcastCompletedAreaList(v.rowBroadcastCompletedAreaList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WriteReplaceWarningResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APWriteReplaceWarningResponseIEValue(&v, &s)
	return s
}

// AreaScopeOfMDT represents the ASN.1 CHOICE type AreaScopeOfMDT.
type AreaScopeOfMDT struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	CellBased          *s25.CellBasedMDT     `json:"CellBased,omitempty"`
	TABased            *s40.TABasedMDT       `json:"TABased,omitempty"`
	PLMNWide           *struct{}             `json:"PLMNWide,omitempty"`
	TAIBased           *TAIBasedMDT          `json:"TAIBased,omitempty"`
}

// AreaScopeOfQMC represents the ASN.1 CHOICE type AreaScopeOfQMC.
type AreaScopeOfQMC struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	CellBased          *s25.CellBasedQMC     `json:"CellBased,omitempty"`
	TABased            *s40.TABasedQMC       `json:"TABased,omitempty"`
	TAIBased           *TAIBasedQMC          `json:"TAIBased,omitempty"`
	PLMNAreaBased      *s23.PLMNAreaBasedQMC `json:"PLMNAreaBased,omitempty"`
}

// BroadcastCancelledAreaList represents the ASN.1 CHOICE type BroadcastCancelledAreaList.
type BroadcastCancelledAreaList struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	Choice                   int
	perPadding               aper.CompletePadding         `json:"-"`
	perOpenTypePadding       aper.CompletePadding         `json:"-"`
	UnknownExtension         *aper.ChoiceExtension        `json:"UnknownExtension,omitempty"`
	CellIDCancelled          s20.CellIDCancelled          `json:"CellIDCancelled,omitzero"`
	TAICancelled             TAICancelled                 `json:"TAICancelled,omitzero"`
	EmergencyAreaIDCancelled s25.EmergencyAreaIDCancelled `json:"EmergencyAreaIDCancelled,omitzero"`
}

// BroadcastCompletedAreaList represents the ASN.1 CHOICE type BroadcastCompletedAreaList.
type BroadcastCompletedAreaList struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	Choice                   int
	perPadding               aper.CompletePadding         `json:"-"`
	perOpenTypePadding       aper.CompletePadding         `json:"-"`
	UnknownExtension         *aper.ChoiceExtension        `json:"UnknownExtension,omitempty"`
	CellIDBroadcast          s20.CellIDBroadcast          `json:"CellIDBroadcast,omitzero"`
	TAIBroadcast             TAIBroadcast                 `json:"TAIBroadcast,omitzero"`
	EmergencyAreaIDBroadcast s26.EmergencyAreaIDBroadcast `json:"EmergencyAreaIDBroadcast,omitzero"`
}

// SourceeNBID represents the ASN.1 type SourceeNB-ID (SEQUENCE).
type SourceeNBID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalENBID       s21.GlobalENBID                   `asn1:"tag:0,context,implicit"`
	SelectedTAI       s40.TAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s13.SourceeNBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	perPadding        aper.CompletePadding              `asn1:"-" json:"-"`
}

// TAIBasedMDT represents the ASN.1 type TAIBasedMDT (SEQUENCE).
type TAIBasedMDT struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	TAIListforMDT      TAIListforMDT                     `asn1:"tag:0,context,implicit"`
	tAIListforMDTIndef bool                              `asn1:"-" json:"-"`
	IEExtensions       s13.TAIBasedMDTExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                              `asn1:"-" json:"-"`
	extCount           int64                             `asn1:"-" json:"-"`
	extPresent         []bool                            `asn1:"-" json:"-"`
	extData            [][]byte                          `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type TAIListforMDT = []s40.TAI
type TAIListforWarning = []s40.TAI
type TAIBroadcast = []TAIBroadcastItem

// TAIBroadcastItem represents the ASN.1 type TAI-Broadcast-Item (SEQUENCE).
type TAIBroadcastItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	TAI                     s40.TAI                                `asn1:"tag:0,context,implicit"`
	CompletedCellinTAI      s20.CompletedCellinTAI                 `asn1:"tag:1,context,implicit"`
	completedCellinTAIIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions            s13.TAIBroadcastItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                   `asn1:"-" json:"-"`
	extCount                int64                                  `asn1:"-" json:"-"`
	extPresent              []bool                                 `asn1:"-" json:"-"`
	extData                 [][]byte                               `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}
type TAICancelled = []TAICancelledItem

// TAICancelledItem represents the ASN.1 type TAI-Cancelled-Item (SEQUENCE).
type TAICancelledItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	TAI                     s40.TAI                                `asn1:"tag:0,context,implicit"`
	CancelledCellinTAI      s20.CancelledCellinTAI                 `asn1:"tag:1,context,implicit"`
	cancelledCellinTAIIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions            s13.TAICancelledItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                   `asn1:"-" json:"-"`
	extCount                int64                                  `asn1:"-" json:"-"`
	extPresent              []bool                                 `asn1:"-" json:"-"`
	extData                 [][]byte                               `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// TAIBasedQMC represents the ASN.1 type TAIBasedQMC (SEQUENCE).
type TAIBasedQMC struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	TAIListforQMC      TAIListforQMC                     `asn1:"tag:0,context,implicit"`
	tAIListforQMCIndef bool                              `asn1:"-" json:"-"`
	IEExtensions       s13.TAIBasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                              `asn1:"-" json:"-"`
	extCount           int64                             `asn1:"-" json:"-"`
	extPresent         []bool                            `asn1:"-" json:"-"`
	extData            [][]byte                          `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type TAIListforQMC = []s40.TAI
type TAIListForRestart = []s40.TAI

// WarningAreaList represents the ASN.1 CHOICE type WarningAreaList.
type WarningAreaList struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	received                   bool
	withoutReplay              bool
	receivedAbsolute           bool
	receivedBytes              aper.WireSpan
	receivedLocation           aper.Location
	Choice                     int
	perPadding                 aper.CompletePadding    `json:"-"`
	perOpenTypePadding         aper.CompletePadding    `json:"-"`
	UnknownExtension           *aper.ChoiceExtension   `json:"UnknownExtension,omitempty"`
	CellIDList                 s20.ECGIList            `json:"CellIDList,omitzero"`
	TrackingAreaListforWarning TAIListforWarning       `json:"TrackingAreaListforWarning,omitzero"`
	EmergencyAreaIDList        s00.EmergencyAreaIDList `json:"EmergencyAreaIDList,omitzero"`
}

// MarshalAPER encodes AreaScopeOfMDT to APER format.
func (v *AreaScopeOfMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *AreaScopeOfMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "AreaScopeOfMDT:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "AreaScopeOfMDT:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "AreaScopeOfMDT:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "AreaScopeOfMDT:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 3 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-3-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.AreaScopeOfMDTChoiceTAIBased:
			if v.TAIBased == nil {
				return fmt.Errorf("choice alternative tAIBased is nil")
			}
			if err := v.TAIBased.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIBased: %w", err)
			}
		default:
			return fmt.Errorf("unknown AreaScopeOfMDT extension choice %d", v.Choice)
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
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.AreaScopeOfMDTChoiceCellBased:
		if v.CellBased == nil {
			return fmt.Errorf("choice alternative cellBased is nil")
		}
		if err := s25.BridgeCellBasedMDTMethodMarshalAPERTo(v.CellBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellBased: %w", err)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		if v.TABased == nil {
			return fmt.Errorf("choice alternative tABased is nil")
		}
		if err := s40.BridgeTABasedMDTMethodMarshalAPERTo(v.TABased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tABased: %w", err)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
	default:
		return fmt.Errorf("unknown AreaScopeOfMDT choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes AreaScopeOfMDT from APER format.
func (v *AreaScopeOfMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AreaScopeOfMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	bb.EnterComponent("AreaScopeOfMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "AreaScopeOfMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *AreaScopeOfMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AreaScopeOfMDT{}
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
		if extIdx >= 1 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(3) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 3 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.AreaScopeOfMDTChoiceTAIBased:
			extensionPath = "TAIBased"
			toleranceMark_taibased := inner.EnterComponent("TAIBased")
			var dec_taibased TAIBasedMDT
			if err := dec_taibased.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TAIBased")
			}
			if err := aper.ChargeValue(inner, dec_taibased); err != nil {
				return err
			}
			v.TAIBased = &dec_taibased
			inner.LeaveComponent(toleranceMark_taibased)
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.AreaScopeOfMDTChoiceCellBased:
		toleranceMark_cellbased := bb.EnterComponent("CellBased")
		var dec_cellbased s25.CellBasedMDT
		if err := s25.BridgeCellBasedMDTMethodUnmarshalAPERFrom(&dec_cellbased, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellBased")
		}
		if err := aper.ChargeValue(bb, dec_cellbased); err != nil {
			return err
		}
		v.CellBased = &dec_cellbased
		bb.LeaveComponent(toleranceMark_cellbased)
	case s00.AreaScopeOfMDTChoiceTABased:
		toleranceMark_tabased := bb.EnterComponent("TABased")
		var dec_tabased s40.TABasedMDT
		if err := s40.BridgeTABasedMDTMethodUnmarshalAPERFrom(&dec_tabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "TABased")
		}
		if err := aper.ChargeValue(bb, dec_tabased); err != nil {
			return err
		}
		v.TABased = &dec_tabased
		bb.LeaveComponent(toleranceMark_tabased)
	case s00.AreaScopeOfMDTChoicePLMNWide:
		v.PLMNWide = new(struct{})
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes AreaScopeOfQMC to APER format.
func (v *AreaScopeOfQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *AreaScopeOfQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "AreaScopeOfQMC:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "AreaScopeOfQMC:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "AreaScopeOfQMC:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "AreaScopeOfQMC:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case s00.AreaScopeOfQMCChoiceCellBased:
		if v.CellBased == nil {
			return fmt.Errorf("choice alternative cellBased is nil")
		}
		if err := s25.BridgeCellBasedQMCMethodMarshalAPERTo(v.CellBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellBased: %w", err)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		if v.TABased == nil {
			return fmt.Errorf("choice alternative tABased is nil")
		}
		if err := s40.BridgeTABasedQMCMethodMarshalAPERTo(v.TABased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tABased: %w", err)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		if v.TAIBased == nil {
			return fmt.Errorf("choice alternative tAIBased is nil")
		}
		if err := v.TAIBased.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tAIBased: %w", err)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		if v.PLMNAreaBased == nil {
			return fmt.Errorf("choice alternative pLMNAreaBased is nil")
		}
		if err := s23.BridgePLMNAreaBasedQMCMethodMarshalAPERTo(v.PLMNAreaBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding pLMNAreaBased: %w", err)
		}
	default:
		return fmt.Errorf("unknown AreaScopeOfQMC choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes AreaScopeOfQMC from APER format.
func (v *AreaScopeOfQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AreaScopeOfQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	bb.EnterComponent("AreaScopeOfQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "AreaScopeOfQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *AreaScopeOfQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AreaScopeOfQMC{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.AreaScopeOfQMCChoiceCellBased:
		toleranceMark_cellbased := bb.EnterComponent("CellBased")
		var dec_cellbased s25.CellBasedQMC
		if err := s25.BridgeCellBasedQMCMethodUnmarshalAPERFrom(&dec_cellbased, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellBased")
		}
		if err := aper.ChargeValue(bb, dec_cellbased); err != nil {
			return err
		}
		v.CellBased = &dec_cellbased
		bb.LeaveComponent(toleranceMark_cellbased)
	case s00.AreaScopeOfQMCChoiceTABased:
		toleranceMark_tabased := bb.EnterComponent("TABased")
		var dec_tabased s40.TABasedQMC
		if err := s40.BridgeTABasedQMCMethodUnmarshalAPERFrom(&dec_tabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "TABased")
		}
		if err := aper.ChargeValue(bb, dec_tabased); err != nil {
			return err
		}
		v.TABased = &dec_tabased
		bb.LeaveComponent(toleranceMark_tabased)
	case s00.AreaScopeOfQMCChoiceTAIBased:
		toleranceMark_taibased := bb.EnterComponent("TAIBased")
		var dec_taibased TAIBasedQMC
		if err := dec_taibased.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TAIBased")
		}
		if err := aper.ChargeValue(bb, dec_taibased); err != nil {
			return err
		}
		v.TAIBased = &dec_taibased
		bb.LeaveComponent(toleranceMark_taibased)
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		toleranceMark_plmnareabased := bb.EnterComponent("PLMNAreaBased")
		var dec_plmnareabased s23.PLMNAreaBasedQMC
		if err := s23.BridgePLMNAreaBasedQMCMethodUnmarshalAPERFrom(&dec_plmnareabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "PLMNAreaBased")
		}
		if err := aper.ChargeValue(bb, dec_plmnareabased); err != nil {
			return err
		}
		v.PLMNAreaBased = &dec_plmnareabased
		bb.LeaveComponent(toleranceMark_plmnareabased)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes BroadcastCancelledAreaList to APER format.
func (v *BroadcastCancelledAreaList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *BroadcastCancelledAreaList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "BroadcastCancelledAreaList:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "BroadcastCancelledAreaList:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "BroadcastCancelledAreaList:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "BroadcastCancelledAreaList:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.CellIDCancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidcancelled, fragmentLength_cellidcancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_cellidcancelled < 0 || fragmentOffset_cellidcancelled > int64(len(v.CellIDCancelled)) || fragmentLength_cellidcancelled < 0 || fragmentLength_cellidcancelled > int64(len(v.CellIDCancelled[fragmentOffset_cellidcancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.CellIDCancelled[fragmentOffset_cellidcancelled : fragmentOffset_cellidcancelled+fragmentLength_cellidcancelled] {
				if err := s20.BridgeCellIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding cellID-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellID-Cancelled: %w", err)
		}
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.TAICancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taicancelled, fragmentLength_taicancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_taicancelled < 0 || fragmentOffset_taicancelled > int64(len(v.TAICancelled)) || fragmentLength_taicancelled < 0 || fragmentLength_taicancelled > int64(len(v.TAICancelled[fragmentOffset_taicancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.TAICancelled[fragmentOffset_taicancelled : fragmentOffset_taicancelled+fragmentLength_taicancelled] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding tAI-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding tAI-Cancelled: %w", err)
		}
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.EmergencyAreaIDCancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidcancelled, fragmentLength_emergencyareaidcancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_emergencyareaidcancelled < 0 || fragmentOffset_emergencyareaidcancelled > int64(len(v.EmergencyAreaIDCancelled)) || fragmentLength_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled > int64(len(v.EmergencyAreaIDCancelled[fragmentOffset_emergencyareaidcancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EmergencyAreaIDCancelled[fragmentOffset_emergencyareaidcancelled : fragmentOffset_emergencyareaidcancelled+fragmentLength_emergencyareaidcancelled] {
				if err := s25.BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding emergencyAreaID-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding emergencyAreaID-Cancelled: %w", err)
		}
	default:
		return fmt.Errorf("unknown BroadcastCancelledAreaList choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BroadcastCancelledAreaList from APER format.
func (v *BroadcastCancelledAreaList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BroadcastCancelledAreaList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	bb.EnterComponent("BroadcastCancelledAreaList")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BroadcastCancelledAreaList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *BroadcastCancelledAreaList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BroadcastCancelledAreaList{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		toleranceMark_cellidcancelled := bb.EnterComponent("CellIDCancelled")
		tmp_cellidcancelled := make(s20.CellIDCancelled, 0)
		_, errCollection_cellidcancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidcancelled, fragmentLength_cellidcancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_cellidcancelled < 0 || fragmentLength_cellidcancelled < 0 || fragmentLength_cellidcancelled > int64(^uint(0)>>1) || fragmentOffset_cellidcancelled > int64(^uint(0)>>1)-fragmentLength_cellidcancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_cellidcancelled; i++ {
				var elem s20.CellIDCancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_cellidcancelled + i)
				if err := s20.BridgeCellIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDCancelled[%d]", fragmentOffset_cellidcancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_cellidcancelled, elem); err != nil {
					return err
				} else {
					tmp_cellidcancelled = next
				}
			}
			return nil
		})
		if errCollection_cellidcancelled != nil {
			return runtime.WrapDecodePath(errCollection_cellidcancelled, "CellIDCancelled")
		}
		v.CellIDCancelled = tmp_cellidcancelled
		bb.LeaveComponent(toleranceMark_cellidcancelled)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		toleranceMark_taicancelled := bb.EnterComponent("TAICancelled")
		tmp_taicancelled := make(TAICancelled, 0)
		_, errCollection_taicancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taicancelled, fragmentLength_taicancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_taicancelled < 0 || fragmentLength_taicancelled < 0 || fragmentLength_taicancelled > int64(^uint(0)>>1) || fragmentOffset_taicancelled > int64(^uint(0)>>1)-fragmentLength_taicancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_taicancelled; i++ {
				var elem TAICancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_taicancelled + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TAICancelled[%d]", fragmentOffset_taicancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_taicancelled, elem); err != nil {
					return err
				} else {
					tmp_taicancelled = next
				}
			}
			return nil
		})
		if errCollection_taicancelled != nil {
			return runtime.WrapDecodePath(errCollection_taicancelled, "TAICancelled")
		}
		v.TAICancelled = tmp_taicancelled
		bb.LeaveComponent(toleranceMark_taicancelled)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		toleranceMark_emergencyareaidcancelled := bb.EnterComponent("EmergencyAreaIDCancelled")
		tmp_emergencyareaidcancelled := make(s25.EmergencyAreaIDCancelled, 0)
		_, errCollection_emergencyareaidcancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidcancelled, fragmentLength_emergencyareaidcancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled > int64(^uint(0)>>1) || fragmentOffset_emergencyareaidcancelled > int64(^uint(0)>>1)-fragmentLength_emergencyareaidcancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_emergencyareaidcancelled; i++ {
				var elem s25.EmergencyAreaIDCancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_emergencyareaidcancelled + i)
				if err := s25.BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelled[%d]", fragmentOffset_emergencyareaidcancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_emergencyareaidcancelled, elem); err != nil {
					return err
				} else {
					tmp_emergencyareaidcancelled = next
				}
			}
			return nil
		})
		if errCollection_emergencyareaidcancelled != nil {
			return runtime.WrapDecodePath(errCollection_emergencyareaidcancelled, "EmergencyAreaIDCancelled")
		}
		v.EmergencyAreaIDCancelled = tmp_emergencyareaidcancelled
		bb.LeaveComponent(toleranceMark_emergencyareaidcancelled)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes BroadcastCompletedAreaList to APER format.
func (v *BroadcastCompletedAreaList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *BroadcastCompletedAreaList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "BroadcastCompletedAreaList:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "BroadcastCompletedAreaList:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "BroadcastCompletedAreaList:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "BroadcastCompletedAreaList:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.BroadcastCompletedAreaListChoiceCellIDBroadcast:
		if err := aper.EncodeCollection(bb, int64(len(v.CellIDBroadcast)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidbroadcast, fragmentLength_cellidbroadcast int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_cellidbroadcast < 0 || fragmentOffset_cellidbroadcast > int64(len(v.CellIDBroadcast)) || fragmentLength_cellidbroadcast < 0 || fragmentLength_cellidbroadcast > int64(len(v.CellIDBroadcast[fragmentOffset_cellidbroadcast:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.CellIDBroadcast[fragmentOffset_cellidbroadcast : fragmentOffset_cellidbroadcast+fragmentLength_cellidbroadcast] {
				if err := s20.BridgeCellIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding cellID-Broadcast element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellID-Broadcast: %w", err)
		}
	case s00.BroadcastCompletedAreaListChoiceTAIBroadcast:
		if err := aper.EncodeCollection(bb, int64(len(v.TAIBroadcast)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taibroadcast, fragmentLength_taibroadcast int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_taibroadcast < 0 || fragmentOffset_taibroadcast > int64(len(v.TAIBroadcast)) || fragmentLength_taibroadcast < 0 || fragmentLength_taibroadcast > int64(len(v.TAIBroadcast[fragmentOffset_taibroadcast:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.TAIBroadcast[fragmentOffset_taibroadcast : fragmentOffset_taibroadcast+fragmentLength_taibroadcast] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding tAI-Broadcast element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding tAI-Broadcast: %w", err)
		}
	case s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast:
		if err := aper.EncodeCollection(bb, int64(len(v.EmergencyAreaIDBroadcast)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidbroadcast, fragmentLength_emergencyareaidbroadcast int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_emergencyareaidbroadcast < 0 || fragmentOffset_emergencyareaidbroadcast > int64(len(v.EmergencyAreaIDBroadcast)) || fragmentLength_emergencyareaidbroadcast < 0 || fragmentLength_emergencyareaidbroadcast > int64(len(v.EmergencyAreaIDBroadcast[fragmentOffset_emergencyareaidbroadcast:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EmergencyAreaIDBroadcast[fragmentOffset_emergencyareaidbroadcast : fragmentOffset_emergencyareaidbroadcast+fragmentLength_emergencyareaidbroadcast] {
				if err := s26.BridgeEmergencyAreaIDBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding emergencyAreaID-Broadcast element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding emergencyAreaID-Broadcast: %w", err)
		}
	default:
		return fmt.Errorf("unknown BroadcastCompletedAreaList choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BroadcastCompletedAreaList from APER format.
func (v *BroadcastCompletedAreaList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BroadcastCompletedAreaList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCompletedAreaList")
	}
	bb.EnterComponent("BroadcastCompletedAreaList")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCompletedAreaList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BroadcastCompletedAreaList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCompletedAreaList")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *BroadcastCompletedAreaList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BroadcastCompletedAreaList{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.BroadcastCompletedAreaListChoiceCellIDBroadcast:
		toleranceMark_cellidbroadcast := bb.EnterComponent("CellIDBroadcast")
		tmp_cellidbroadcast := make(s20.CellIDBroadcast, 0)
		_, errCollection_cellidbroadcast := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidbroadcast, fragmentLength_cellidbroadcast int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_cellidbroadcast < 0 || fragmentLength_cellidbroadcast < 0 || fragmentLength_cellidbroadcast > int64(^uint(0)>>1) || fragmentOffset_cellidbroadcast > int64(^uint(0)>>1)-fragmentLength_cellidbroadcast {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_cellidbroadcast; i++ {
				var elem s20.CellIDBroadcastItem
				elementMark := bb.EnterIndex(fragmentOffset_cellidbroadcast + i)
				if err := s20.BridgeCellIDBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDBroadcast[%d]", fragmentOffset_cellidbroadcast+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_cellidbroadcast, elem); err != nil {
					return err
				} else {
					tmp_cellidbroadcast = next
				}
			}
			return nil
		})
		if errCollection_cellidbroadcast != nil {
			return runtime.WrapDecodePath(errCollection_cellidbroadcast, "CellIDBroadcast")
		}
		v.CellIDBroadcast = tmp_cellidbroadcast
		bb.LeaveComponent(toleranceMark_cellidbroadcast)
	case s00.BroadcastCompletedAreaListChoiceTAIBroadcast:
		toleranceMark_taibroadcast := bb.EnterComponent("TAIBroadcast")
		tmp_taibroadcast := make(TAIBroadcast, 0)
		_, errCollection_taibroadcast := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taibroadcast, fragmentLength_taibroadcast int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_taibroadcast < 0 || fragmentLength_taibroadcast < 0 || fragmentLength_taibroadcast > int64(^uint(0)>>1) || fragmentOffset_taibroadcast > int64(^uint(0)>>1)-fragmentLength_taibroadcast {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_taibroadcast; i++ {
				var elem TAIBroadcastItem
				elementMark := bb.EnterIndex(fragmentOffset_taibroadcast + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBroadcast[%d]", fragmentOffset_taibroadcast+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_taibroadcast, elem); err != nil {
					return err
				} else {
					tmp_taibroadcast = next
				}
			}
			return nil
		})
		if errCollection_taibroadcast != nil {
			return runtime.WrapDecodePath(errCollection_taibroadcast, "TAIBroadcast")
		}
		v.TAIBroadcast = tmp_taibroadcast
		bb.LeaveComponent(toleranceMark_taibroadcast)
	case s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast:
		toleranceMark_emergencyareaidbroadcast := bb.EnterComponent("EmergencyAreaIDBroadcast")
		tmp_emergencyareaidbroadcast := make(s26.EmergencyAreaIDBroadcast, 0)
		_, errCollection_emergencyareaidbroadcast := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidbroadcast, fragmentLength_emergencyareaidbroadcast int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_emergencyareaidbroadcast < 0 || fragmentLength_emergencyareaidbroadcast < 0 || fragmentLength_emergencyareaidbroadcast > int64(^uint(0)>>1) || fragmentOffset_emergencyareaidbroadcast > int64(^uint(0)>>1)-fragmentLength_emergencyareaidbroadcast {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_emergencyareaidbroadcast; i++ {
				var elem s26.EmergencyAreaIDBroadcastItem
				elementMark := bb.EnterIndex(fragmentOffset_emergencyareaidbroadcast + i)
				if err := s26.BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDBroadcast[%d]", fragmentOffset_emergencyareaidbroadcast+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_emergencyareaidbroadcast, elem); err != nil {
					return err
				} else {
					tmp_emergencyareaidbroadcast = next
				}
			}
			return nil
		})
		if errCollection_emergencyareaidbroadcast != nil {
			return runtime.WrapDecodePath(errCollection_emergencyareaidbroadcast, "EmergencyAreaIDBroadcast")
		}
		v.EmergencyAreaIDBroadcast = tmp_emergencyareaidbroadcast
		bb.LeaveComponent(toleranceMark_emergencyareaidbroadcast)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type BridgeAsn1cAPERRecommendedENBListListValue struct{ Value s40.RecommendedENBList }

// MarshalAPER encodes SourceeNBID to APER format.
func (v *SourceeNBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SourceeNBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s21.BridgeGlobalENBIDMethodMarshalAPERTo(&v.GlobalENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-ENB-ID: %w", err)
	}
	if err := s40.BridgeTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	return nil
}

// UnmarshalAPER decodes SourceeNBID from APER format.
func (v *SourceeNBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SourceeNBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBID")
	}
	bb.EnterComponent("SourceeNBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceeNBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SourceeNBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBID{}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_globalenbid := bb.EnterComponent("GlobalENBID")
	if err := s21.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&v.GlobalENBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	bb.LeaveComponent(toleranceMark_globalenbid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.SourceeNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.SourceeNBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeSourceeNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TAIBasedMDT to APER format.
func (v *TAIBasedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIBasedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAIListforMDT)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistformdt, fragmentLength_tailistformdt int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_tailistformdt < 0 || fragmentOffset_tailistformdt > int64(len(v.TAIListforMDT)) || fragmentLength_tailistformdt < 0 || fragmentLength_tailistformdt > int64(len(v.TAIListforMDT[fragmentOffset_tailistformdt:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAIListforMDT[fragmentOffset_tailistformdt : fragmentOffset_tailistformdt+fragmentLength_tailistformdt] {
			if err := s40.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIListforMDT element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAIListforMDT: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTAIBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIBasedMDT from APER format.
func (v *TAIBasedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIBasedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	bb.EnterComponent("TAIBasedMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBasedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	v.perPadding = padding
	return nil
}
func (v *TAIBasedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedMDT{}
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
	toleranceMark_tailistformdt := bb.EnterComponent("TAIListforMDT")
	v.TAIListforMDT = make(TAIListforMDT, 0)
	_, errCollection_tailistformdt := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistformdt, fragmentLength_tailistformdt int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_tailistformdt < 0 || fragmentLength_tailistformdt < 0 || fragmentLength_tailistformdt > int64(^uint(0)>>1) || fragmentOffset_tailistformdt > int64(^uint(0)>>1)-fragmentLength_tailistformdt {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_tailistformdt; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_tailistformdt + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAIListforMDT[%d]", fragmentOffset_tailistformdt+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.TAIListforMDT, elem); err != nil {
				return err
			} else {
				v.TAIListforMDT = next
			}
		}
		return nil
	})
	if errCollection_tailistformdt != nil {
		return runtime.WrapDecodePath(errCollection_tailistformdt, "TAIListforMDT")
	}
	bb.LeaveComponent(toleranceMark_tailistformdt)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TAIBasedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TAIBasedMDTExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTAIBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERTAIListforMDTListValue struct{ Value TAIListforMDT }
type BridgeAsn1cAPERTAIListforWarningListValue struct{ Value TAIListforWarning }
type BridgeAsn1cAPERTAIBroadcastListValue struct{ Value TAIBroadcast }

// MarshalAPER encodes TAIBroadcastItem to APER format.
func (v *TAIBroadcastItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIBroadcastItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s40.BridgeTAIMethodMarshalAPERTo(&v.TAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding tAI: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CompletedCellinTAI)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_completedcellintai, fragmentLength_completedcellintai int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_completedcellintai < 0 || fragmentOffset_completedcellintai > int64(len(v.CompletedCellinTAI)) || fragmentLength_completedcellintai < 0 || fragmentLength_completedcellintai > int64(len(v.CompletedCellinTAI[fragmentOffset_completedcellintai:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CompletedCellinTAI[fragmentOffset_completedcellintai : fragmentOffset_completedcellintai+fragmentLength_completedcellintai] {
			if err := s20.BridgeCompletedCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding completedCellinTAI element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding completedCellinTAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTAIBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIBroadcastItem from APER format.
func (v *TAIBroadcastItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIBroadcastItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcastItem")
	}
	bb.EnterComponent("TAIBroadcastItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcastItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBroadcastItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcastItem")
	}
	v.perPadding = padding
	return nil
}
func (v *TAIBroadcastItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBroadcastItem{}
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
	toleranceMark_tai := bb.EnterComponent("TAI")
	if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&v.TAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	bb.LeaveComponent(toleranceMark_tai)
	toleranceMark_completedcellintai := bb.EnterComponent("CompletedCellinTAI")
	v.CompletedCellinTAI = make(s20.CompletedCellinTAI, 0)
	_, errCollection_completedcellintai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_completedcellintai, fragmentLength_completedcellintai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_completedcellintai < 0 || fragmentLength_completedcellintai < 0 || fragmentLength_completedcellintai > int64(^uint(0)>>1) || fragmentOffset_completedcellintai > int64(^uint(0)>>1)-fragmentLength_completedcellintai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_completedcellintai; i++ {
			var elem s20.CompletedCellinTAIItem
			elementMark := bb.EnterIndex(fragmentOffset_completedcellintai + i)
			if err := s20.BridgeCompletedCellinTAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinTAI[%d]", fragmentOffset_completedcellintai+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CompletedCellinTAI, elem); err != nil {
				return err
			} else {
				v.CompletedCellinTAI = next
			}
		}
		return nil
	})
	if errCollection_completedcellintai != nil {
		return runtime.WrapDecodePath(errCollection_completedcellintai, "CompletedCellinTAI")
	}
	bb.LeaveComponent(toleranceMark_completedcellintai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TAIBroadcastItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TAIBroadcastItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTAIBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERTAICancelledListValue struct{ Value TAICancelled }

// MarshalAPER encodes TAICancelledItem to APER format.
func (v *TAICancelledItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAICancelledItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s40.BridgeTAIMethodMarshalAPERTo(&v.TAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding tAI: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CancelledCellinTAI)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellintai, fragmentLength_cancelledcellintai int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cancelledcellintai < 0 || fragmentOffset_cancelledcellintai > int64(len(v.CancelledCellinTAI)) || fragmentLength_cancelledcellintai < 0 || fragmentLength_cancelledcellintai > int64(len(v.CancelledCellinTAI[fragmentOffset_cancelledcellintai:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CancelledCellinTAI[fragmentOffset_cancelledcellintai : fragmentOffset_cancelledcellintai+fragmentLength_cancelledcellintai] {
			if err := s20.BridgeCancelledCellinTAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cancelledCellinTAI element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cancelledCellinTAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTAICancelledItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAICancelledItem from APER format.
func (v *TAICancelledItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAICancelledItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAICancelledItem")
	}
	bb.EnterComponent("TAICancelledItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAICancelledItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAICancelledItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAICancelledItem")
	}
	v.perPadding = padding
	return nil
}
func (v *TAICancelledItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAICancelledItem{}
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
	toleranceMark_tai := bb.EnterComponent("TAI")
	if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&v.TAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	bb.LeaveComponent(toleranceMark_tai)
	toleranceMark_cancelledcellintai := bb.EnterComponent("CancelledCellinTAI")
	v.CancelledCellinTAI = make(s20.CancelledCellinTAI, 0)
	_, errCollection_cancelledcellintai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellintai, fragmentLength_cancelledcellintai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_cancelledcellintai < 0 || fragmentLength_cancelledcellintai < 0 || fragmentLength_cancelledcellintai > int64(^uint(0)>>1) || fragmentOffset_cancelledcellintai > int64(^uint(0)>>1)-fragmentLength_cancelledcellintai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cancelledcellintai; i++ {
			var elem s20.CancelledCellinTAIItem
			elementMark := bb.EnterIndex(fragmentOffset_cancelledcellintai + i)
			if err := s20.BridgeCancelledCellinTAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinTAI[%d]", fragmentOffset_cancelledcellintai+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CancelledCellinTAI, elem); err != nil {
				return err
			} else {
				v.CancelledCellinTAI = next
			}
		}
		return nil
	})
	if errCollection_cancelledcellintai != nil {
		return runtime.WrapDecodePath(errCollection_cancelledcellintai, "CancelledCellinTAI")
	}
	bb.LeaveComponent(toleranceMark_cancelledcellintai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TAICancelledItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TAICancelledItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTAICancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TAIBasedQMC to APER format.
func (v *TAIBasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIBasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAIListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistforqmc, fragmentLength_tailistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_tailistforqmc < 0 || fragmentOffset_tailistforqmc > int64(len(v.TAIListforQMC)) || fragmentLength_tailistforqmc < 0 || fragmentLength_tailistforqmc > int64(len(v.TAIListforQMC[fragmentOffset_tailistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAIListforQMC[fragmentOffset_tailistforqmc : fragmentOffset_tailistforqmc+fragmentLength_tailistforqmc] {
			if err := s40.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAIListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTAIBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIBasedQMC from APER format.
func (v *TAIBasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TAIBasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	bb.EnterComponent("TAIBasedQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	v.perPadding = padding
	return nil
}
func (v *TAIBasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedQMC{}
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
	toleranceMark_tailistforqmc := bb.EnterComponent("TAIListforQMC")
	v.TAIListforQMC = make(TAIListforQMC, 0)
	_, errCollection_tailistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistforqmc, fragmentLength_tailistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_tailistforqmc < 0 || fragmentLength_tailistforqmc < 0 || fragmentLength_tailistforqmc > int64(^uint(0)>>1) || fragmentOffset_tailistforqmc > int64(^uint(0)>>1)-fragmentLength_tailistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_tailistforqmc; i++ {
			var elem s40.TAI
			elementMark := bb.EnterIndex(fragmentOffset_tailistforqmc + i)
			if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAIListforQMC[%d]", fragmentOffset_tailistforqmc+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.TAIListforQMC, elem); err != nil {
				return err
			} else {
				v.TAIListforQMC = next
			}
		}
		return nil
	})
	if errCollection_tailistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_tailistforqmc, "TAIListforQMC")
	}
	bb.LeaveComponent(toleranceMark_tailistforqmc)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TAIBasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TAIBasedQMCExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTAIBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERTAIListforQMCListValue struct{ Value TAIListforQMC }
type BridgeAsn1cAPERTAIListForRestartListValue struct{ Value TAIListForRestart }

// MarshalAPER encodes WarningAreaList to APER format.
func (v *WarningAreaList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *WarningAreaList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "WarningAreaList:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "WarningAreaList:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "WarningAreaList:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "WarningAreaList:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.WarningAreaListChoiceCellIDList:
		if err := aper.EncodeCollection(bb, int64(len(v.CellIDList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidlist, fragmentLength_cellidlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_cellidlist < 0 || fragmentOffset_cellidlist > int64(len(v.CellIDList)) || fragmentLength_cellidlist < 0 || fragmentLength_cellidlist > int64(len(v.CellIDList[fragmentOffset_cellidlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.CellIDList[fragmentOffset_cellidlist : fragmentOffset_cellidlist+fragmentLength_cellidlist] {
				if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding cellIDList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellIDList: %w", err)
		}
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		if err := aper.EncodeCollection(bb, int64(len(v.TrackingAreaListforWarning)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_trackingarealistforwarning, fragmentLength_trackingarealistforwarning int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_trackingarealistforwarning < 0 || fragmentOffset_trackingarealistforwarning > int64(len(v.TrackingAreaListforWarning)) || fragmentLength_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning > int64(len(v.TrackingAreaListforWarning[fragmentOffset_trackingarealistforwarning:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.TrackingAreaListforWarning[fragmentOffset_trackingarealistforwarning : fragmentOffset_trackingarealistforwarning+fragmentLength_trackingarealistforwarning] {
				if err := s40.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding trackingAreaListforWarning element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding trackingAreaListforWarning: %w", err)
		}
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		if err := aper.EncodeCollection(bb, int64(len(v.EmergencyAreaIDList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidlist, fragmentLength_emergencyareaidlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_emergencyareaidlist < 0 || fragmentOffset_emergencyareaidlist > int64(len(v.EmergencyAreaIDList)) || fragmentLength_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist > int64(len(v.EmergencyAreaIDList[fragmentOffset_emergencyareaidlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EmergencyAreaIDList[fragmentOffset_emergencyareaidlist : fragmentOffset_emergencyareaidlist+fragmentLength_emergencyareaidlist] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
					return fmt.Errorf("encoding emergencyAreaIDList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding emergencyAreaIDList: %w", err)
		}
	default:
		return fmt.Errorf("unknown WarningAreaList choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes WarningAreaList from APER format.
func (v *WarningAreaList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *WarningAreaList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	bb.EnterComponent("WarningAreaList")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WarningAreaList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *WarningAreaList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WarningAreaList{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.WarningAreaListChoiceCellIDList:
		toleranceMark_cellidlist := bb.EnterComponent("CellIDList")
		tmp_cellidlist := make(s20.ECGIList, 0)
		_, errCollection_cellidlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidlist, fragmentLength_cellidlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_cellidlist < 0 || fragmentLength_cellidlist < 0 || fragmentLength_cellidlist > int64(^uint(0)>>1) || fragmentOffset_cellidlist > int64(^uint(0)>>1)-fragmentLength_cellidlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_cellidlist; i++ {
				var elem s20.EUTRANCGI
				elementMark := bb.EnterIndex(fragmentOffset_cellidlist + i)
				if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDList[%d]", fragmentOffset_cellidlist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_cellidlist, elem); err != nil {
					return err
				} else {
					tmp_cellidlist = next
				}
			}
			return nil
		})
		if errCollection_cellidlist != nil {
			return runtime.WrapDecodePath(errCollection_cellidlist, "CellIDList")
		}
		v.CellIDList = tmp_cellidlist
		bb.LeaveComponent(toleranceMark_cellidlist)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		toleranceMark_trackingarealistforwarning := bb.EnterComponent("TrackingAreaListforWarning")
		tmp_trackingarealistforwarning := make(TAIListforWarning, 0)
		_, errCollection_trackingarealistforwarning := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_trackingarealistforwarning, fragmentLength_trackingarealistforwarning int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning > int64(^uint(0)>>1) || fragmentOffset_trackingarealistforwarning > int64(^uint(0)>>1)-fragmentLength_trackingarealistforwarning {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_trackingarealistforwarning; i++ {
				var elem s40.TAI
				elementMark := bb.EnterIndex(fragmentOffset_trackingarealistforwarning + i)
				if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TrackingAreaListforWarning[%d]", fragmentOffset_trackingarealistforwarning+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_trackingarealistforwarning, elem); err != nil {
					return err
				} else {
					tmp_trackingarealistforwarning = next
				}
			}
			return nil
		})
		if errCollection_trackingarealistforwarning != nil {
			return runtime.WrapDecodePath(errCollection_trackingarealistforwarning, "TrackingAreaListforWarning")
		}
		v.TrackingAreaListforWarning = tmp_trackingarealistforwarning
		bb.LeaveComponent(toleranceMark_trackingarealistforwarning)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		toleranceMark_emergencyareaidlist := bb.EnterComponent("EmergencyAreaIDList")
		tmp_emergencyareaidlist := make(s00.EmergencyAreaIDList, 0)
		_, errCollection_emergencyareaidlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidlist, fragmentLength_emergencyareaidlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
			if fragmentOffset_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist > int64(^uint(0)>>1) || fragmentOffset_emergencyareaidlist > int64(^uint(0)>>1)-fragmentLength_emergencyareaidlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_emergencyareaidlist; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDList[%d]", fragmentOffset_emergencyareaidlist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_emergencyareaidlist, val); err != nil {
					return err
				} else {
					tmp_emergencyareaidlist = next
				}
			}
			return nil
		})
		if errCollection_emergencyareaidlist != nil {
			return runtime.WrapDecodePath(errCollection_emergencyareaidlist, "EmergencyAreaIDList")
		}
		v.EmergencyAreaIDList = tmp_emergencyareaidlist
		bb.LeaveComponent(toleranceMark_emergencyareaidlist)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AreaScopeOfMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "AreaScopeOfMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AreaScopeOfMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AreaScopeOfMDT) WithoutReplay() AreaScopeOfMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AreaScopeOfMDT
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AreaScopeOfQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "AreaScopeOfQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AreaScopeOfQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AreaScopeOfQMC) WithoutReplay() AreaScopeOfQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AreaScopeOfQMC
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BroadcastCancelledAreaList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BroadcastCancelledAreaList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BroadcastCancelledAreaList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BroadcastCancelledAreaList) WithoutReplay() BroadcastCancelledAreaList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BroadcastCancelledAreaList
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BroadcastCompletedAreaList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BroadcastCompletedAreaList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BroadcastCompletedAreaList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BroadcastCompletedAreaList) WithoutReplay() BroadcastCompletedAreaList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BroadcastCompletedAreaList
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SourceeNBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceeNBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceeNBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceeNBID) WithoutReplay() SourceeNBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceeNBID
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBasedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBasedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBasedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBasedMDT) WithoutReplay() TAIBasedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBasedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBasedQMC) WithoutReplay() TAIBasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBroadcastItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBroadcastItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBroadcastItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBroadcastItem) WithoutReplay() TAIBroadcastItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBroadcastItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAICancelledItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAICancelledItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAICancelledItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAICancelledItem) WithoutReplay() TAICancelledItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAICancelledItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WarningAreaList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "WarningAreaList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WarningAreaList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WarningAreaList) WithoutReplay() WarningAreaList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WarningAreaList
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *TAIBasedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIBasedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIBasedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAIBasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIBasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIBasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAIBroadcastItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIBroadcastItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIBroadcastItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAICancelledItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAICancelledItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAICancelledItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAICancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAICancelledItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAICancelledItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAICancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AreaScopeOfMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AreaScopeOfMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AreaScopeOfMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAreaScopeOfMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AreaScopeOfMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AreaScopeOfMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AreaScopeOfMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AreaScopeOfMDT")
}
func (v *AreaScopeOfMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AreaScopeOfMDT")
}
func (v *AreaScopeOfMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAreaScopeOfMDT(v, &s)
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
func (v *AreaScopeOfMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AreaScopeOfMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AreaScopeOfQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AreaScopeOfQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AreaScopeOfQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAreaScopeOfQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AreaScopeOfQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AreaScopeOfQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AreaScopeOfQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AreaScopeOfQMC")
}
func (v *AreaScopeOfQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AreaScopeOfQMC")
}
func (v *AreaScopeOfQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAreaScopeOfQMC(v, &s)
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
func (v *AreaScopeOfQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AreaScopeOfQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BroadcastCancelledAreaList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BroadcastCancelledAreaList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BroadcastCancelledAreaList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BroadcastCancelledAreaList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBroadcastCancelledAreaList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BroadcastCancelledAreaList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BroadcastCancelledAreaList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BroadcastCancelledAreaList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BroadcastCancelledAreaList")
}
func (v *BroadcastCancelledAreaList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BroadcastCancelledAreaList")
}
func (v *BroadcastCancelledAreaList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBroadcastCancelledAreaList(v, &s)
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
func (v *BroadcastCancelledAreaList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BroadcastCancelledAreaList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BroadcastCompletedAreaList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BroadcastCompletedAreaList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BroadcastCompletedAreaList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BroadcastCompletedAreaList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBroadcastCompletedAreaList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BroadcastCompletedAreaList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BroadcastCompletedAreaList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BroadcastCompletedAreaList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BroadcastCompletedAreaList")
}
func (v *BroadcastCompletedAreaList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BroadcastCompletedAreaList")
}
func (v *BroadcastCompletedAreaList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBroadcastCompletedAreaList(v, &s)
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
func (v *BroadcastCompletedAreaList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BroadcastCompletedAreaList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SourceeNBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceeNBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceeNBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceeNBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceeNBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceeNBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceeNBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceeNBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceeNBID")
}
func (v *SourceeNBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceeNBID")
}
func (v *SourceeNBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceeNBID(v, &s)
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
func (v *SourceeNBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceeNBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIBasedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBasedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBasedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBasedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBasedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBasedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBasedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBasedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBasedMDT")
}
func (v *TAIBasedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBasedMDT")
}
func (v *TAIBasedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBasedMDT(v, &s)
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
func (v *TAIBasedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBasedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIBasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBasedQMC")
}
func (v *TAIBasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBasedQMC")
}
func (v *TAIBasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBasedQMC(v, &s)
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
func (v *TAIBasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIBroadcastItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBroadcastItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBroadcastItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBroadcastItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBroadcastItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBroadcastItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBroadcastItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBroadcastItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBroadcastItem")
}
func (v *TAIBroadcastItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBroadcastItem")
}
func (v *TAIBroadcastItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBroadcastItem(v, &s)
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
func (v *TAIBroadcastItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBroadcastItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAICancelledItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAICancelledItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAICancelledItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAICancelledItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAICancelledItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAICancelledItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAICancelledItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAICancelledItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAICancelledItem")
}
func (v *TAICancelledItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAICancelledItem")
}
func (v *TAICancelledItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAICancelledItem(v, &s)
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
func (v *TAICancelledItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAICancelledItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WarningAreaList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WarningAreaList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WarningAreaList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WarningAreaList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWarningAreaList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WarningAreaList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WarningAreaList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WarningAreaList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WarningAreaList")
}
func (v *WarningAreaList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WarningAreaList")
}
func (v *WarningAreaList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWarningAreaList(v, &s)
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
func (v *WarningAreaList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WarningAreaList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *AreaScopeOfMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AreaScopeOfMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAreaScopeOfMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AreaScopeOfMDT{}
		return report, aper.OperationError(err, "AreaScopeOfMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AreaScopeOfMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *AreaScopeOfQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AreaScopeOfQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAreaScopeOfQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AreaScopeOfQMC{}
		return report, aper.OperationError(err, "AreaScopeOfQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AreaScopeOfQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BroadcastCancelledAreaList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BroadcastCancelledAreaList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BroadcastCancelledAreaList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBroadcastCancelledAreaList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BroadcastCancelledAreaList{}
		return report, aper.OperationError(err, "BroadcastCancelledAreaList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BroadcastCancelledAreaList")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BroadcastCompletedAreaList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BroadcastCompletedAreaList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BroadcastCompletedAreaList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBroadcastCompletedAreaList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BroadcastCompletedAreaList{}
		return report, aper.OperationError(err, "BroadcastCompletedAreaList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BroadcastCompletedAreaList")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SourceeNBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceeNBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceeNBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceeNBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceeNBID{}
		return report, aper.OperationError(err, "SourceeNBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceeNBID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIBasedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBasedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBasedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBasedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBasedMDT{}
		return report, aper.OperationError(err, "TAIBasedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBasedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIBasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBasedQMC{}
		return report, aper.OperationError(err, "TAIBasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIBroadcastItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBroadcastItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBroadcastItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBroadcastItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBroadcastItem{}
		return report, aper.OperationError(err, "TAIBroadcastItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBroadcastItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAICancelledItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAICancelledItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAICancelledItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAICancelledItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAICancelledItem{}
		return report, aper.OperationError(err, "TAICancelledItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAICancelledItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WarningAreaList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WarningAreaList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WarningAreaList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWarningAreaList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WarningAreaList{}
		return report, aper.OperationError(err, "WarningAreaList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WarningAreaList")
}

// NewAreaScopeOfMDTUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewAreaScopeOfMDTUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	value := AreaScopeOfMDT{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTUnknownExtension")
}

// NewAreaScopeOfQMCUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewAreaScopeOfQMCUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	value := AreaScopeOfQMC{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCUnknownExtension")
}

// NewBroadcastCancelledAreaListUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewBroadcastCancelledAreaListUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	value := BroadcastCancelledAreaList{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListUnknownExtension")
}

// NewBroadcastCompletedAreaListUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewBroadcastCompletedAreaListUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (BroadcastCompletedAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListUnknownExtension")
	}
	value := BroadcastCompletedAreaList{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListUnknownExtension")
	}
	return value, aper.OperationError(nil, "BroadcastCompletedAreaListUnknownExtension")
}

type KillRequestIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMessageIdentifier      *s00.MessageIdentifier
	rowSerialNumber           *s00.SerialNumber
	rowWarningAreaList        *WarningAreaList
	rowKillAllWarningMessages *s00.KillAllWarningMessages
}

func (v KillRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(111):
		return v.rowMessageIdentifier != nil
	case s00.ProtocolIEID(112):
		return v.rowSerialNumber != nil
	case s00.ProtocolIEID(113):
		return v.rowWarningAreaList != nil
	case s00.ProtocolIEID(191):
		return v.rowKillAllWarningMessages != nil
	}
	return false
}

// Opaque returns the retained opaque open value of KillRequestIEValue and reports whether the opaque alternative is selected.
func (v *KillRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (KillRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs"}}
}
func (KillRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(113):
		return aper.UnknownSelector
	case s00.ProtocolIEID(191):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsWarningAreaList returns the selected WarningAreaList value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsWarningAreaList() (*WarningAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(113) || v.rowWarningAreaList == nil {
		return nil, false
	}
	return v.rowWarningAreaList, true
}

// AsKillAllWarningMessages returns the selected KillAllWarningMessages value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsKillAllWarningMessages() (*s00.KillAllWarningMessages, bool) {
	if v == nil || v.id != s00.ProtocolIEID(191) || v.rowKillAllWarningMessages == nil {
		return nil, false
	}
	return v.rowKillAllWarningMessages, true
}
func (v KillRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (KillRequestIEValue, error) {
	out := KillRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(111):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MessageIdentifier, error) {
			var v struct{ Value s00.MessageIdentifier }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowMessageIdentifier = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(112):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SerialNumber, error) {
			var v struct{ Value s00.SerialNumber }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowSerialNumber = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(113):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value WarningAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WarningAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WarningAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowWarningAreaList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(191):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, false, aper.EnumerationSource{KnownExtensions: 0, Path: "KillAllWarningMessages"})
		value := s00.KillAllWarningMessages(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "KillAllWarningMessages:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowKillAllWarningMessages = &value
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
func (v KillRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v KillRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(111):
		if v.rowMessageIdentifier == nil {
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-MessageIdentifier:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MessageIdentifier, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MessageIdentifier }{Value: value}
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
		})(*v.rowMessageIdentifier, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(112):
		if v.rowSerialNumber == nil {
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-SerialNumber:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SerialNumber, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SerialNumber }{Value: value}
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
		})(*v.rowSerialNumber, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(113):
		if v.rowWarningAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-WarningAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowWarningAreaList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(191):
		if v.rowKillAllWarningMessages == nil {
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-KillAllWarningMessages:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowKillAllWarningMessages), 1, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "KillRequestIEValue:", v.id)
	}
}

type KillResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMessageIdentifier          *s00.MessageIdentifier
	rowSerialNumber               *s00.SerialNumber
	rowBroadcastCancelledAreaList *BroadcastCancelledAreaList
	rowCriticalityDiagnostics     *s26.CriticalityDiagnostics
}

func (v KillResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(111):
		return v.rowMessageIdentifier != nil
	case s00.ProtocolIEID(112):
		return v.rowSerialNumber != nil
	case s00.ProtocolIEID(141):
		return v.rowBroadcastCancelledAreaList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of KillResponseIEValue and reports whether the opaque alternative is selected.
func (v *KillResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (KillResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs"}}
}
func (KillResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(141):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsBroadcastCancelledAreaList returns the selected BroadcastCancelledAreaList value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsBroadcastCancelledAreaList() (*BroadcastCancelledAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(141) || v.rowBroadcastCancelledAreaList == nil {
		return nil, false
	}
	return v.rowBroadcastCancelledAreaList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v KillResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (KillResponseIEValue, error) {
	out := KillResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(111):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MessageIdentifier, error) {
			var v struct{ Value s00.MessageIdentifier }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowMessageIdentifier = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(112):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SerialNumber, error) {
			var v struct{ Value s00.SerialNumber }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowSerialNumber = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(141):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BroadcastCancelledAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BroadcastCancelledAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BroadcastCancelledAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBroadcastCancelledAreaList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
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
func (v KillResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v KillResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(111):
		if v.rowMessageIdentifier == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-MessageIdentifier:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MessageIdentifier, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MessageIdentifier }{Value: value}
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
		})(*v.rowMessageIdentifier, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(112):
		if v.rowSerialNumber == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-SerialNumber:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SerialNumber, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SerialNumber }{Value: value}
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
		})(*v.rowSerialNumber, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(141):
		if v.rowBroadcastCancelledAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-BroadcastCancelledAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBroadcastCancelledAreaList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "KillResponseIEValue:", v.id)
	}
}

type UplinkNASTransportIEValue struct {
	id                               s00.ProtocolIEID
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           aper.OpaqueOpenType
	isOpaque                         bool
	rowMMEUES1APID                   *s00.MMEUES1APID
	rowENBUES1APID                   *s00.ENBUES1APID
	rowNASPDU                        *s00.NASPDU
	rowEUTRANCGI                     *s20.EUTRANCGI
	rowTAI                           *s40.TAI
	rowGWTransportLayerAddress       *s00.TransportLayerAddress
	rowSIPTOLGWTransportLayerAddress *s00.TransportLayerAddress
	rowLHNID                         *s00.LHNID
	rowPSCellInformation             *s23.PSCellInformation
	rowLTENTNTAIInformation          *s22.LTENTNTAIInformation
}

func (v UplinkNASTransportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(26):
		return v.rowNASPDU != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(155):
		return v.rowGWTransportLayerAddress != nil
	case s00.ProtocolIEID(184):
		return v.rowSIPTOLGWTransportLayerAddress != nil
	case s00.ProtocolIEID(186):
		return v.rowLHNID != nil
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UplinkNASTransportIEValue and reports whether the opaque alternative is selected.
func (v *UplinkNASTransportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UplinkNASTransportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs"}}
}
func (UplinkNASTransportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(26):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(155):
		return aper.UnknownSelector
	case s00.ProtocolIEID(184):
		return aper.UnknownSelector
	case s00.ProtocolIEID(186):
		return aper.UnknownSelector
	case s00.ProtocolIEID(288):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsNASPDU returns the selected NASPDU value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsEUTRANCGI() (*s20.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsTAI() (*s40.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsGWTransportLayerAddress returns the selected GWTransportLayerAddress value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(155) || v.rowGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowGWTransportLayerAddress, true
}

// AsSIPTOLGWTransportLayerAddress returns the selected SIPTOLGWTransportLayerAddress value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsSIPTOLGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(184) || v.rowSIPTOLGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSIPTOLGWTransportLayerAddress, true
}

// AsLHNID returns the selected LHNID value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}

// AsPSCellInformation returns the selected PSCellInformation value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsPSCellInformation() (*s23.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of UplinkNASTransportIEValue and reports whether that alternative is active.
func (v *UplinkNASTransportIEValue) AsLTENTNTAIInformation() (*s22.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v UplinkNASTransportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UplinkNASTransportIEValue, error) {
	out := UplinkNASTransportIEValue{id: id}
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
	case s00.ProtocolIEID(26):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NASPDU, error) {
			var v struct{ Value s00.NASPDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.NASPDU(val_value)
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
		out.rowNASPDU = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.EUTRANCGI
		child := scope
		if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		*s20.BridgeEUTRANCGIFieldPerPadding(&value) = padding
		*s20.BridgeEUTRANCGIFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeEUTRANCGIFieldReceivedBytes(&value))
		*s20.BridgeEUTRANCGIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(67):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s40.TAI
		child := scope
		if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s40.BridgeTAIFieldPerPadding(&value) = padding
		*s40.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s40.BridgeTAIFieldReceivedBytes(&value))
		*s40.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(155):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowGWTransportLayerAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(184):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowSIPTOLGWTransportLayerAddress = &value
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
	case s00.ProtocolIEID(288):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.PSCellInformation
		child := scope
		if err := s23.BridgePSCellInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PSCellInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PSCellInformation")
		if err != nil {
			return out, err
		}
		*s23.BridgePSCellInformationFieldPerPadding(&value) = padding
		*s23.BridgePSCellInformationFieldReceived(&value) = true
		raw.RetainContents(s23.BridgePSCellInformationFieldReceivedBytes(&value))
		*s23.BridgePSCellInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPSCellInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(339):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.LTENTNTAIInformation
		child := scope
		if err := s22.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s22.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s22.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s22.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
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
func (v UplinkNASTransportIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UplinkNASTransportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(26):
		if v.rowNASPDU == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-NAS-PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NASPDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.NASPDU }{Value: value}
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
		})(*v.rowNASPDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-EUTRAN-CGI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeEUTRANCGIMethodMarshalAPERBudget(v.rowEUTRANCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(67):
		if v.rowTAI == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s40.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(155):
		if v.rowGWTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-GW-TransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowGWTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(184):
		if v.rowSIPTOLGWTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-SIPTO-L-GW-TransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOLGWTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(186):
		if v.rowLHNID == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-LHN-ID:")
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
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-PSCellInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgePSCellInformationMethodMarshalAPERBudget(v.rowPSCellInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkNASTransport-IEs.id-LTE-NTN-TAI-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UplinkNASTransportIEValue:", v.id)
	}
}

type WriteReplaceWarningResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMessageIdentifier          *s00.MessageIdentifier
	rowSerialNumber               *s00.SerialNumber
	rowBroadcastCompletedAreaList *BroadcastCompletedAreaList
	rowCriticalityDiagnostics     *s26.CriticalityDiagnostics
}

func (v WriteReplaceWarningResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(111):
		return v.rowMessageIdentifier != nil
	case s00.ProtocolIEID(112):
		return v.rowSerialNumber != nil
	case s00.ProtocolIEID(120):
		return v.rowBroadcastCompletedAreaList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of WriteReplaceWarningResponseIEValue and reports whether the opaque alternative is selected.
func (v *WriteReplaceWarningResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (WriteReplaceWarningResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs"}}
}
func (WriteReplaceWarningResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(120):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsBroadcastCompletedAreaList returns the selected BroadcastCompletedAreaList value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsBroadcastCompletedAreaList() (*BroadcastCompletedAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(120) || v.rowBroadcastCompletedAreaList == nil {
		return nil, false
	}
	return v.rowBroadcastCompletedAreaList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v WriteReplaceWarningResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WriteReplaceWarningResponseIEValue, error) {
	out := WriteReplaceWarningResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(111):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MessageIdentifier, error) {
			var v struct{ Value s00.MessageIdentifier }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowMessageIdentifier = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(112):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SerialNumber, error) {
			var v struct{ Value s00.SerialNumber }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowSerialNumber = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(120):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BroadcastCompletedAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BroadcastCompletedAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BroadcastCompletedAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBroadcastCompletedAreaList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
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
func (v WriteReplaceWarningResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v WriteReplaceWarningResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(111):
		if v.rowMessageIdentifier == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-MessageIdentifier:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MessageIdentifier, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MessageIdentifier }{Value: value}
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
		})(*v.rowMessageIdentifier, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(112):
		if v.rowSerialNumber == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-SerialNumber:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SerialNumber, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SerialNumber }{Value: value}
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
		})(*v.rowSerialNumber, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(120):
		if v.rowBroadcastCompletedAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-BroadcastCompletedAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBroadcastCompletedAreaList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WriteReplaceWarningResponseIEValue:", v.id)
	}
}

type KillResponseIETable struct{}

func KillResponseIEs() KillResponseIETable { return KillResponseIETable{} }

// ID returns the ASN.1 object-set identity of KillResponseIETable.
func (KillResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by KillResponseIETable.
func (KillResponseIETable) Table() s00.KillResponseIEValueIETable {
	return func() s00.KillResponseIEValueIETable {
		sealed := s00.KillResponseIEValueIETable{}
		*s00.BridgeKillResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (KillResponseIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of KillResponseIETable.
func (t KillResponseIETable) MessageIdentifier() KillResponseMessageIdentifierIEBinding {
	return KillResponseMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding KillResponseIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMessageIdentifierValueCodecFieldCapture(&sealed) = func(v s00.MessageIdentifier, options aper.DecodeState) (s00.MessageIdentifier, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMessageIdentifier(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeMessageIdentifierValueCodecFieldCompare(&sealed) = func(v s00.MessageIdentifier, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMessageIdentifier(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeMessageIdentifierValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MessageIdentifier"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MessageIdentifier) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *KillResponseIEValue) (*s00.MessageIdentifier, bool) { return value.AsMessageIdentifier() }}
}
func (KillResponseIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of KillResponseIETable.
func (t KillResponseIETable) SerialNumber() KillResponseSerialNumberIEBinding {
	return KillResponseSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s02.SerialNumberValueCodec {
		sealed := s02.SerialNumberValueCodec{}
		*s02.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s02.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding KillResponseIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSerialNumberValueCodecFieldCapture(&sealed) = func(v s00.SerialNumber, options aper.DecodeState) (s00.SerialNumber, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSerialNumber(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSerialNumberValueCodecFieldCompare(&sealed) = func(v s00.SerialNumber, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSerialNumber(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeSerialNumberValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SerialNumber"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SerialNumber) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *KillResponseIEValue) (*s00.SerialNumber, bool) { return value.AsSerialNumber() }}
}
func (KillResponseIETable) infoBroadcastCancelledAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(141), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BroadcastCancelledAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-BroadcastCancelledAreaList"}}}
}

// BroadcastCancelledAreaList returns the typed binding for the BroadcastCancelledAreaList row of KillResponseIETable.
func (t KillResponseIETable) BroadcastCancelledAreaList() KillResponseBroadcastCancelledAreaListIEBinding {
	return KillResponseBroadcastCancelledAreaListIEBinding{info: t.infoBroadcastCancelledAreaList(), codec: BroadcastCancelledAreaListValueCodec{path: "BroadcastCancelledAreaList",
		decode: func(data []byte, options aper.DecodeState) (BroadcastCancelledAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BroadcastCancelledAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BroadcastCancelledAreaList")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(141), raw)
			if err != nil {
				var empty BroadcastCancelledAreaList
				return empty, runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
			}
			value, ok := decoded.AsBroadcastCancelledAreaList()
			if !ok {
				var empty BroadcastCancelledAreaList
				return empty, fmt.Errorf("binding KillResponseIEs.id-BroadcastCancelledAreaList: no selected value")
			}
			return *value, nil
		},
		encode: func(value BroadcastCancelledAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(141), rowBroadcastCancelledAreaList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BroadcastCancelledAreaList, options aper.DecodeState) (BroadcastCancelledAreaList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBroadcastCancelledAreaList(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}, compare: func(v BroadcastCancelledAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBroadcastCancelledAreaList(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastCancelledAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BroadcastCancelledAreaList) KillResponseIEValue {
		return KillResponseIEValue{id: s00.ProtocolIEID(141), rowBroadcastCancelledAreaList: &value}
	}, get: func(value *KillResponseIEValue) (*BroadcastCancelledAreaList, bool) {
		return value.AsBroadcastCancelledAreaList()
	}}
}
func (KillResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of KillResponseIETable.
func (t KillResponseIETable) CriticalityDiagnostics() KillResponseCriticalityDiagnosticsIEBinding {
	return KillResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding KillResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *KillResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in KillResponseIETable.
func (t KillResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (KillResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(141):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-BroadcastCancelledAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return KillResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return KillResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return KillResponseIEField{Id: id, Criticality: criticality, Value: KillResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type LocationReportIETable struct{}

func LocationReportIEs() LocationReportIETable { return LocationReportIETable{} }

// ID returns the ASN.1 object-set identity of LocationReportIETable.
func (LocationReportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LocationReportIETable.
func (LocationReportIETable) Table() s00.LocationReportIEValueIETable {
	return func() s00.LocationReportIEValueIETable {
		sealed := s00.LocationReportIEValueIETable{}
		*s00.BridgeLocationReportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (LocationReportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of LocationReportIETable.
func (t LocationReportIETable) MMEUES1APID() s40.LocationReportMMEUES1APIDIEBinding {
	return func() s40.LocationReportMMEUES1APIDIEBinding {
		sealed := s40.LocationReportMMEUES1APIDIEBinding{}
		*s40.BridgeLocationReportMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s40.BridgeLocationReportMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding LocationReportIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s40.BridgeLocationReportIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		*s40.BridgeLocationReportMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeLocationReportIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (LocationReportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of LocationReportIETable.
func (t LocationReportIETable) ENBUES1APID() s40.LocationReportENBUES1APIDIEBinding {
	return func() s40.LocationReportENBUES1APIDIEBinding {
		sealed := s40.LocationReportENBUES1APIDIEBinding{}
		*s40.BridgeLocationReportENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s40.BridgeLocationReportENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding LocationReportIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s40.BridgeLocationReportIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s40.BridgeLocationReportENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeLocationReportIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (LocationReportIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of LocationReportIETable.
func (t LocationReportIETable) EUTRANCGI() s40.LocationReportEUTRANCGIIEBinding {
	return func() s40.LocationReportEUTRANCGIIEBinding {
		sealed := s40.LocationReportEUTRANCGIIEBinding{}
		*s40.BridgeLocationReportEUTRANCGIIEBindingFieldInfo(&sealed) = t.infoEUTRANCGI()
		*s40.BridgeLocationReportEUTRANCGIIEBindingFieldCodec(&sealed) = func() s20.EUTRANCGIValueCodec {
			sealed := s20.EUTRANCGIValueCodec{}
			*s20.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
			*s20.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.EUTRANCGI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.EUTRANCGI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EUTRANCGI")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(100), raw)
				if err != nil {
					var empty s20.EUTRANCGI
					return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
				}
				value, ok := decoded.AsEUTRANCGI()
				if !ok {
					var empty s20.EUTRANCGI
					return empty, fmt.Errorf("binding LocationReportIEs.id-EUTRAN-CGI: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s20.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
					*s40.BridgeLocationReportIEValueFieldRowEUTRANCGI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s20.EUTRANCGI, options aper.DecodeState) (s20.EUTRANCGI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.
					Begin()
				s20.BridgeCaptureS1APEUTRANCGI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s20.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APEUTRANCGI(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s20.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s40.BridgeLocationReportEUTRANCGIIEBindingFieldInject(&sealed) = func(value s20.EUTRANCGI) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s40.BridgeLocationReportIEValueFieldRowEUTRANCGI(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportEUTRANCGIIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s20.EUTRANCGI, bool) { return value.AsEUTRANCGI() }
		return sealed
	}()
}
func (LocationReportIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of LocationReportIETable.
func (t LocationReportIETable) TAI() LocationReportTAIIEBinding {
	return LocationReportTAIIEBinding{info: t.infoTAI(), codec: TAIValueCodec{path: "TAI",
		decode: func(data []byte, options aper.DecodeState) (s40.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero s40.LocationReportIEValue
			decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s40.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s40.TAI
				return empty, fmt.Errorf("binding LocationReportIEs.id-TAI: no selected value")
			}
			return *value, nil
		},
		encode: func(value s40.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s40.BridgeLocationReportIEValueFieldRowTAI(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s40.TAI, options aper.DecodeState) (s40.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}, compare: func(v s40.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s40.TAI) s40.LocationReportIEValue {
		return func() s40.LocationReportIEValue {
			sealed := s40.LocationReportIEValue{}
			*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
			*s40.BridgeLocationReportIEValueFieldRowTAI(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s40.LocationReportIEValue) (*s40.TAI, bool) { return value.AsTAI() }}
}
func (LocationReportIETable) infoRequestType() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(98), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-RequestType"}}}
}

// RequestType returns the typed binding for the RequestType row of LocationReportIETable.
func (t LocationReportIETable) RequestType() s40.LocationReportRequestTypeIEBinding {
	return func() s40.LocationReportRequestTypeIEBinding {
		sealed := s40.LocationReportRequestTypeIEBinding{}
		*s40.BridgeLocationReportRequestTypeIEBindingFieldInfo(&sealed) = t.infoRequestType()
		*s40.BridgeLocationReportRequestTypeIEBindingFieldCodec(&sealed) = func() s31.RequestTypeValueCodec {
			sealed := s31.RequestTypeValueCodec{}
			*s31.BridgeRequestTypeValueCodecFieldPath(&sealed) = "RequestType"
			*s31.BridgeRequestTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.RequestType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s31.RequestType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("RequestType")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(98), raw)
				if err != nil {
					var empty s31.RequestType
					return empty, runtime.WrapDecodePath(err, "RequestType")
				}
				value, ok := decoded.AsRequestType()
				if !ok {
					var empty s31.RequestType
					return empty, fmt.Errorf("binding LocationReportIEs.id-RequestType: no selected value")
				}
				return *value, nil
			}
			*s31.BridgeRequestTypeValueCodecFieldEncode(&sealed) = func(value s31.RequestType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
					*s40.BridgeLocationReportIEValueFieldRowRequestType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s31.BridgeRequestTypeValueCodecFieldCapture(&sealed) = func(v s31.RequestType, options aper.DecodeState) (s31.RequestType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s31.BridgeCaptureS1APRequestType(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s31.BridgeRequestTypeValueCodecFieldCompare(&sealed) = func(v s31.RequestType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s31.BridgeCompareS1APRequestType(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s31.BridgeRequestTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s40.BridgeLocationReportRequestTypeIEBindingFieldInject(&sealed) = func(value s31.RequestType) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s40.BridgeLocationReportIEValueFieldRowRequestType(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportRequestTypeIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s31.RequestType, bool) { return value.AsRequestType() }
		return sealed
	}()
}
func (LocationReportIETable) infoPSCellInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-PSCellInformation"}}}
}

// PSCellInformation returns the typed binding for the PSCellInformation row of LocationReportIETable.
func (t LocationReportIETable) PSCellInformation() s40.LocationReportPSCellInformationIEBinding {
	return func() s40.LocationReportPSCellInformationIEBinding {
		sealed := s40.LocationReportPSCellInformationIEBinding{}
		*s40.BridgeLocationReportPSCellInformationIEBindingFieldInfo(&sealed) = t.infoPSCellInformation()
		*s40.BridgeLocationReportPSCellInformationIEBindingFieldCodec(&sealed) = func() s23.PSCellInformationValueCodec {
			sealed := s23.PSCellInformationValueCodec{}
			*s23.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
			*s23.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PSCellInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s23.PSCellInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PSCellInformation")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(288), raw)
				if err != nil {
					var empty s23.PSCellInformation
					return empty, runtime.WrapDecodePath(err, "PSCellInformation")
				}
				value, ok := decoded.AsPSCellInformation()
				if !ok {
					var empty s23.PSCellInformation
					return empty, fmt.Errorf("binding LocationReportIEs.id-PSCellInformation: no selected value")
				}
				return *value, nil
			}
			*s23.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s23.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
					*s40.BridgeLocationReportIEValueFieldRowPSCellInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s23.BridgePSCellInformationValueCodecFieldCapture(&sealed) = func(v s23.PSCellInformation, options aper.DecodeState) (s23.PSCellInformation, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s23.BridgeCaptureS1APPSCellInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s23.BridgePSCellInformationValueCodecFieldCompare(&sealed) = func(v s23.PSCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s23.BridgeCompareS1APPSCellInformation(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s23.BridgePSCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PSCellInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s40.BridgeLocationReportPSCellInformationIEBindingFieldInject(&sealed) = func(value s23.PSCellInformation) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s40.BridgeLocationReportIEValueFieldRowPSCellInformation(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportPSCellInformationIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s23.PSCellInformation, bool) {
			return value.AsPSCellInformation()
		}
		return sealed
	}()
}
func (LocationReportIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of LocationReportIETable.
func (t LocationReportIETable) LTENTNTAIInformation() s40.LocationReportLTENTNTAIInformationIEBinding {
	return func() s40.LocationReportLTENTNTAIInformationIEBinding {
		sealed := s40.LocationReportLTENTNTAIInformationIEBinding{}
		*s40.BridgeLocationReportLTENTNTAIInformationIEBindingFieldInfo(&sealed) = t.infoLTENTNTAIInformation()
		*s40.BridgeLocationReportLTENTNTAIInformationIEBindingFieldCodec(&sealed) = func() s22.LTENTNTAIInformationValueCodec {
			sealed := s22.LTENTNTAIInformationValueCodec{}
			*s22.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
			*s22.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LTENTNTAIInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s22.LTENTNTAIInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
				var zero s40.LocationReportIEValue
				decoded, err := s40.BridgeLocationReportIEValueMethodDecode(zero, s00.ProtocolIEID(339), raw)
				if err != nil {
					var empty s22.LTENTNTAIInformation
					return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
				}
				value, ok := decoded.AsLTENTNTAIInformation()
				if !ok {
					var empty s22.LTENTNTAIInformation
					return empty, fmt.Errorf("binding LocationReportIEs.id-LTE-NTN-TAI-Information: no selected value")
				}
				return *value, nil
			}
			*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s22.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s40.BridgeLocationReportIEValueMethodEncodeFresh((func() s40.LocationReportIEValue {
					sealed := s40.LocationReportIEValue{}
					*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
					*s40.BridgeLocationReportIEValueFieldRowLTENTNTAIInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s22.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s22.LTENTNTAIInformation, options aper.DecodeState) (s22.LTENTNTAIInformation, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s22.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s22.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s22.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s22.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s22.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s40.BridgeLocationReportLTENTNTAIInformationIEBindingFieldInject(&sealed) = func(value s22.LTENTNTAIInformation) s40.LocationReportIEValue {
			return func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s40.BridgeLocationReportIEValueFieldRowLTENTNTAIInformation(&sealed) = &value
				return sealed
			}()
		}
		*s40.BridgeLocationReportLTENTNTAIInformationIEBindingFieldGet(&sealed) = func(value *s40.LocationReportIEValue) (*s22.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LocationReportIETable.
func (t LocationReportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s40.LocationReportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(98):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-RequestType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(288):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return s40.LocationReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s40.LocationReportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s40.LocationReportIEField{}, aper.OperationError(err, "Opaque")
		}
		return s40.LocationReportIEField{Id: id, Criticality: criticality, Value: func() s40.LocationReportIEValue {
			sealed := s40.LocationReportIEValue{}
			*s40.BridgeLocationReportIEValueFieldId(&sealed) = id
			*s40.BridgeLocationReportIEValueFieldOpaque(&sealed) = opaque
			*s40.BridgeLocationReportIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UplinkNASTransportIETable struct{}

func UplinkNASTransportIEs() UplinkNASTransportIETable { return UplinkNASTransportIETable{} }

// ID returns the ASN.1 object-set identity of UplinkNASTransportIETable.
func (UplinkNASTransportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UplinkNASTransportIETable.
func (UplinkNASTransportIETable) Table() s00.UplinkNASTransportIEValueIETable {
	return func() s00.UplinkNASTransportIEValueIETable {
		sealed := s00.UplinkNASTransportIEValueIETable{}
		*s00.BridgeUplinkNASTransportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UplinkNASTransportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) MMEUES1APID() UplinkNASTransportMMEUES1APIDIEBinding {
	return UplinkNASTransportMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UplinkNASTransportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) ENBUES1APID() UplinkNASTransportENBUES1APIDIEBinding {
	return UplinkNASTransportENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UplinkNASTransportIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-NAS-PDU"}}}
}

// NASPDU returns the typed binding for the NASPDU row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) NASPDU() UplinkNASTransportNASPDUIEBinding {
	return UplinkNASTransportNASPDUIEBinding{info: t.infoNASPDU(), codec: func() s01.NASPDUValueCodec {
		sealed := s01.NASPDUValueCodec{}
		*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
		*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NASPDU")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(26), raw)
			if err != nil {
				var empty s00.NASPDU
				return empty, runtime.WrapDecodePath(err, "NASPDU")
			}
			value, ok := decoded.AsNASPDU()
			if !ok {
				var empty s00.NASPDU
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-NAS-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNASPDUValueCodecFieldCapture(&sealed) = func(v s00.NASPDU, options aper.DecodeState) (s00.NASPDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APNASPDU(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNASPDUValueCodecFieldCompare(&sealed) = func(v s00.NASPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNASPDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNASPDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASPDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NASPDU) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }}
}
func (UplinkNASTransportIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) EUTRANCGI() UplinkNASTransportEUTRANCGIIEBinding {
	return UplinkNASTransportEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s20.EUTRANCGIValueCodec {
		sealed := s20.EUTRANCGIValueCodec{}
		*s20.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s20.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s20.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s20.EUTRANCGI
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s20.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s20.EUTRANCGI, options aper.DecodeState) (s20.EUTRANCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s20.BridgeCaptureS1APEUTRANCGI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s20.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APEUTRANCGI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.EUTRANCGI) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s20.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (UplinkNASTransportIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) TAI() UplinkNASTransportTAIIEBinding {
	return UplinkNASTransportTAIIEBinding{info: t.infoTAI(), codec: TAIValueCodec{path: "TAI",
		decode: func(data []byte, options aper.DecodeState) (s40.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s40.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s40.TAI
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-TAI: no selected value")
			}
			return *value, nil
		},
		encode: func(value s40.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s40.TAI, options aper.DecodeState) (s40.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}, compare: func(v s40.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s40.TAI) UplinkNASTransportIEValue {
		return UplinkNASTransportIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
	}, get: func(value *UplinkNASTransportIEValue) (*s40.TAI, bool) { return value.AsTAI() }}
}
func (UplinkNASTransportIETable) infoGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(155), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-GW-TransportLayerAddress"}}}
}

// GWTransportLayerAddress returns the typed binding for the GWTransportLayerAddress row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) GWTransportLayerAddress() UplinkNASTransportTransportLayerAddressIEBinding {
	return UplinkNASTransportTransportLayerAddressIEBinding{info: t.infoGWTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(155), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
			}
			value, ok := decoded.AsGWTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-GW-TransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(155), rowGWTransportLayerAddress: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APTransportLayerAddress(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TransportLayerAddress) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(155), rowGWTransportLayerAddress: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsGWTransportLayerAddress()
		}}
}
func (UplinkNASTransportIETable) infoSIPTOLGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(184), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-SIPTO-L-GW-TransportLayerAddress"}}}
}

// SIPTOLGWTransportLayerAddress returns the typed binding for the SIPTOLGWTransportLayerAddress row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) SIPTOLGWTransportLayerAddress() UplinkNASTransportTransportLayerAddressIEBinding {
	return UplinkNASTransportTransportLayerAddressIEBinding{info: t.infoSIPTOLGWTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(184), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
			}
			value, ok := decoded.AsSIPTOLGWTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-SIPTO-L-GW-TransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(184), rowSIPTOLGWTransportLayerAddress: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APTransportLayerAddress(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TransportLayerAddress) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(184), rowSIPTOLGWTransportLayerAddress: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSIPTOLGWTransportLayerAddress()
		}}
}
func (UplinkNASTransportIETable) infoLHNID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(186), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LHN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-LHN-ID"}}}
}

// LHNID returns the typed binding for the LHNID row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) LHNID() UplinkNASTransportLHNIDIEBinding {
	return UplinkNASTransportLHNIDIEBinding{info: t.infoLHNID(), codec: func() s01.LHNIDValueCodec {
		sealed := s01.LHNIDValueCodec{}
		*s01.BridgeLHNIDValueCodecFieldPath(&sealed) = "LHNID"
		*s01.BridgeLHNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LHNID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LHNID")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(186), raw)
			if err != nil {
				var empty s00.LHNID
				return empty, runtime.WrapDecodePath(err, "LHNID")
			}
			value, ok := decoded.AsLHNID()
			if !ok {
				var empty s00.LHNID
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-LHN-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLHNIDValueCodecFieldEncode(&sealed) = func(value s00.LHNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeLHNIDValueCodecFieldCapture(&sealed) = func(v s00.LHNID, options aper.DecodeState) (s00.LHNID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLHNID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeLHNIDValueCodecFieldCompare(&sealed) = func(v s00.LHNID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APLHNID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLHNIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LHNID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.LHNID) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s00.LHNID, bool) { return value.AsLHNID() }}
}
func (UplinkNASTransportIETable) infoPSCellInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-PSCellInformation"}}}
}

// PSCellInformation returns the typed binding for the PSCellInformation row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) PSCellInformation() UplinkNASTransportPSCellInformationIEBinding {
	return UplinkNASTransportPSCellInformationIEBinding{info: t.infoPSCellInformation(), codec: func() s23.PSCellInformationValueCodec {
		sealed := s23.PSCellInformationValueCodec{}
		*s23.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
		*s23.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PSCellInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.PSCellInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PSCellInformation")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s23.PSCellInformation
				return empty, runtime.WrapDecodePath(err, "PSCellInformation")
			}
			value, ok := decoded.AsPSCellInformation()
			if !ok {
				var empty s23.PSCellInformation
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-PSCellInformation: no selected value")
			}
			return *value, nil
		}
		*s23.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s23.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgePSCellInformationValueCodecFieldCapture(&sealed) = func(v s23.PSCellInformation, options aper.DecodeState) (s23.PSCellInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APPSCellInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s23.BridgePSCellInformationValueCodecFieldCompare(&sealed) = func(v s23.PSCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APPSCellInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s23.BridgePSCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PSCellInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.PSCellInformation) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s23.PSCellInformation, bool) {
			return value.AsPSCellInformation()
		}}
}
func (UplinkNASTransportIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkNASTransport-IEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) LTENTNTAIInformation() UplinkNASTransportLTENTNTAIInformationIEBinding {
	return UplinkNASTransportLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s22.LTENTNTAIInformationValueCodec {
		sealed := s22.LTENTNTAIInformationValueCodec{}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s22.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero UplinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s22.LTENTNTAIInformation
				return empty, fmt.Errorf("binding UplinkNASTransport-IEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s22.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkNASTransportIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s22.LTENTNTAIInformation, options aper.DecodeState) (s22.LTENTNTAIInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s22.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.LTENTNTAIInformation) UplinkNASTransportIEValue {
			return UplinkNASTransportIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *UplinkNASTransportIEValue) (*s22.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UplinkNASTransportIETable.
func (t UplinkNASTransportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UplinkNASTransportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(155):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(184):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-SIPTO-L-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(186):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-LHN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(288):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return UplinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UplinkNASTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UplinkNASTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		return UplinkNASTransportIEField{Id: id, Criticality: criticality, Value: UplinkNASTransportIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type WriteReplaceWarningResponseIETable struct{}

func WriteReplaceWarningResponseIEs() WriteReplaceWarningResponseIETable {
	return WriteReplaceWarningResponseIETable{}
}

// ID returns the ASN.1 object-set identity of WriteReplaceWarningResponseIETable.
func (WriteReplaceWarningResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by WriteReplaceWarningResponseIETable.
func (WriteReplaceWarningResponseIETable) Table() s00.WriteReplaceWarningResponseIEValueIETable {
	return func() s00.WriteReplaceWarningResponseIEValueIETable {
		sealed := s00.WriteReplaceWarningResponseIEValueIETable{}
		*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (WriteReplaceWarningResponseIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) MessageIdentifier() WriteReplaceWarningResponseMessageIdentifierIEBinding {
	return WriteReplaceWarningResponseMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMessageIdentifierValueCodecFieldCapture(&sealed) = func(v s00.MessageIdentifier, options aper.DecodeState) (s00.MessageIdentifier, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMessageIdentifier(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeMessageIdentifierValueCodecFieldCompare(&sealed) = func(v s00.MessageIdentifier, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMessageIdentifier(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeMessageIdentifierValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MessageIdentifier"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MessageIdentifier) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s00.MessageIdentifier, bool) {
			return value.AsMessageIdentifier()
		}}
}
func (WriteReplaceWarningResponseIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) SerialNumber() WriteReplaceWarningResponseSerialNumberIEBinding {
	return WriteReplaceWarningResponseSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s02.SerialNumberValueCodec {
		sealed := s02.SerialNumberValueCodec{}
		*s02.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s02.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSerialNumberValueCodecFieldCapture(&sealed) = func(v s00.SerialNumber, options aper.DecodeState) (s00.SerialNumber, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSerialNumber(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSerialNumberValueCodecFieldCompare(&sealed) = func(v s00.SerialNumber, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSerialNumber(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeSerialNumberValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SerialNumber"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SerialNumber) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s00.SerialNumber, bool) {
			return value.AsSerialNumber()
		}}
}
func (WriteReplaceWarningResponseIETable) infoBroadcastCompletedAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(120), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BroadcastCompletedAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-BroadcastCompletedAreaList"}}}
}

// BroadcastCompletedAreaList returns the typed binding for the BroadcastCompletedAreaList row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) BroadcastCompletedAreaList() WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding {
	return WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding{info: t.infoBroadcastCompletedAreaList(), codec: BroadcastCompletedAreaListValueCodec{path: "BroadcastCompletedAreaList",
		decode: func(data []byte, options aper.DecodeState) (BroadcastCompletedAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BroadcastCompletedAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BroadcastCompletedAreaList")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(120), raw)
			if err != nil {
				var empty BroadcastCompletedAreaList
				return empty, runtime.WrapDecodePath(err, "BroadcastCompletedAreaList")
			}
			value, ok := decoded.AsBroadcastCompletedAreaList()
			if !ok {
				var empty BroadcastCompletedAreaList
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-BroadcastCompletedAreaList: no selected value")
			}
			return *value, nil
		},
		encode: func(value BroadcastCompletedAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(120), rowBroadcastCompletedAreaList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BroadcastCompletedAreaList, options aper.DecodeState) (BroadcastCompletedAreaList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBroadcastCompletedAreaList(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}, compare: func(v BroadcastCompletedAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBroadcastCompletedAreaList(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastCompletedAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BroadcastCompletedAreaList) WriteReplaceWarningResponseIEValue {
		return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(120), rowBroadcastCompletedAreaList: &value}
	}, get: func(value *WriteReplaceWarningResponseIEValue) (*BroadcastCompletedAreaList, bool) {
		return value.AsBroadcastCompletedAreaList()
	}}
}
func (WriteReplaceWarningResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) CriticalityDiagnostics() WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding {
	return WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WriteReplaceWarningResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(120):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-BroadcastCompletedAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return WriteReplaceWarningResponseIEField{Id: id, Criticality: criticality, Value: WriteReplaceWarningResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AreaScopeOfMDTCodec binds the complete source value type.
func AreaScopeOfMDTCodec() AreaScopeOfMDTValueCodec {
	return AreaScopeOfMDTValueCodec{path: "AreaScopeOfMDT", decode: func(data []byte, options aper.DecodeState) (AreaScopeOfMDT, error) {
		var value AreaScopeOfMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AreaScopeOfMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AreaScopeOfMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AreaScopeOfMDT, options aper.DecodeState) (AreaScopeOfMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAreaScopeOfMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v AreaScopeOfMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APAreaScopeOfMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AreaScopeOfMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// AreaScopeOfQMCCodec binds the complete source value type.
func AreaScopeOfQMCCodec() AreaScopeOfQMCValueCodec {
	return AreaScopeOfQMCValueCodec{path: "AreaScopeOfQMC", decode: func(data []byte, options aper.DecodeState) (AreaScopeOfQMC, error) {
		var value AreaScopeOfQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AreaScopeOfQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AreaScopeOfQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AreaScopeOfQMC, options aper.DecodeState) (AreaScopeOfQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAreaScopeOfQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v AreaScopeOfQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APAreaScopeOfQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AreaScopeOfQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// BroadcastCancelledAreaListCodec binds the complete APER value type.
func BroadcastCancelledAreaListCodec() BroadcastCancelledAreaListValueCodec {
	return KillResponseIEs().BroadcastCancelledAreaList().Codec()
}

// BroadcastCompletedAreaListCodec binds the complete APER value type.
func BroadcastCompletedAreaListCodec() BroadcastCompletedAreaListValueCodec {
	return WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Codec()
}

// SourceeNBIDCodec binds the complete source value type.
func SourceeNBIDCodec() SourceeNBIDValueCodec {
	return SourceeNBIDValueCodec{path: "SourceeNBID", decode: func(data []byte, options aper.DecodeState) (SourceeNBID, error) {
		var value SourceeNBID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SourceeNBID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SourceeNBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SourceeNBID, options aper.DecodeState) (SourceeNBID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSourceeNBID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v SourceeNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSourceeNBID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceeNBID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TAIBasedMDTCodec binds the complete source value type.
func TAIBasedMDTCodec() TAIBasedMDTValueCodec {
	return TAIBasedMDTValueCodec{path: "TAIBasedMDT", decode: func(data []byte, options aper.DecodeState) (TAIBasedMDT, error) {
		var value TAIBasedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAIBasedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAIBasedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAIBasedMDT, options aper.DecodeState) (TAIBasedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTAIBasedMDT(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIBasedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAIBasedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBasedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TAIBasedQMCCodec binds the complete source value type.
func TAIBasedQMCCodec() TAIBasedQMCValueCodec {
	return TAIBasedQMCValueCodec{path: "TAIBasedQMC", decode: func(data []byte, options aper.DecodeState) (TAIBasedQMC, error) {
		var value TAIBasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAIBasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAIBasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAIBasedQMC, options aper.DecodeState) (TAIBasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTAIBasedQMC(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIBasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAIBasedQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TAIBroadcastItemCodec binds the complete source value type.
func TAIBroadcastItemCodec() TAIBroadcastItemValueCodec {
	return TAIBroadcastItemValueCodec{path: "TAIBroadcastItem", decode: func(data []byte, options aper.DecodeState) (TAIBroadcastItem, error) {
		var value TAIBroadcastItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAIBroadcastItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAIBroadcastItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAIBroadcastItem, options aper.DecodeState) (TAIBroadcastItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APTAIBroadcastItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIBroadcastItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAIBroadcastItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBroadcastItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TAICancelledItemCodec binds the complete source value type.
func TAICancelledItemCodec() TAICancelledItemValueCodec {
	return TAICancelledItemValueCodec{path: "TAICancelledItem", decode: func(data []byte, options aper.DecodeState) (TAICancelledItem, error) {
		var value TAICancelledItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAICancelledItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAICancelledItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAICancelledItem, options aper.DecodeState) (TAICancelledItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APTAICancelledItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAICancelledItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAICancelledItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAICancelledItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeAreaScopeOfMDTMethodMarshalAPERBudget(v *AreaScopeOfMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERTo(v *AreaScopeOfMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAreaScopeOfMDTMethodUnmarshalAPERFrom(v *AreaScopeOfMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERBudget(v *AreaScopeOfQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERTo(v *AreaScopeOfQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAreaScopeOfQMCMethodUnmarshalAPERFrom(v *AreaScopeOfQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERBudget(v *BroadcastCancelledAreaList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBroadcastCompletedAreaListMethodMarshalAPERBudget(v *BroadcastCompletedAreaList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeKillRequestIEContainerValueCodecFieldCapture(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, aper.DecodeState) (KillRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEContainerValueCodecFieldCompare(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEContainerValueCodecFieldContext(v *KillRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEContainerValueCodecFieldDecode(v *KillRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEContainer, error) {
	return &v.decode
}
func BridgeKillRequestIEContainerValueCodecFieldEncode(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEContainerValueCodecFieldPath(v *KillRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEFieldFieldReplay(v *KillRequestIEField) *aper.Snapshot { return &v.replay }
func BridgeKillRequestIEFieldFieldWithoutReplay(v *KillRequestIEField) *bool   { return &v.withoutReplay }
func BridgeKillRequestIEFieldMethodMarshalAPERTo(v *KillRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillRequestIEFieldMethodUnmarshalAPERFrom(v *KillRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillRequestIEFieldValueCodecFieldCapture(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, aper.DecodeState) (KillRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEFieldValueCodecFieldCompare(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEFieldValueCodecFieldContext(v *KillRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEFieldValueCodecFieldDecode(v *KillRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEField, error) {
	return &v.decode
}
func BridgeKillRequestIEFieldValueCodecFieldEncode(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEFieldValueCodecFieldPath(v *KillRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldContext(v *KillRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldReceived(v *KillRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldReplay(v *KillRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *KillRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEValueFieldId(v *KillRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeKillRequestIEValueFieldIsOpaque(v *KillRequestIEValue) *bool       { return &v.isOpaque }
func BridgeKillRequestIEValueFieldOpaque(v *KillRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeKillRequestIEValueFieldRowKillAllWarningMessages(v *KillRequestIEValue) **s00.KillAllWarningMessages {
	return &v.rowKillAllWarningMessages
}
func BridgeKillRequestIEValueFieldRowMessageIdentifier(v *KillRequestIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeKillRequestIEValueFieldRowSerialNumber(v *KillRequestIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeKillRequestIEValueFieldRowWarningAreaList(v *KillRequestIEValue) **WarningAreaList {
	return &v.rowWarningAreaList
}
func BridgeKillRequestIEValueMethodCaptureSemantics(v KillRequestIEValue, a0 aper.SemanticCapture) KillRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeKillRequestIEValueMethodCompareSemantics(v KillRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeKillRequestIEValueMethodDecode(v KillRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (KillRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeKillRequestIEValueMethodEncodeFresh(v KillRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeKillRequestIEValueMethodMatchesID(v KillRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeKillRequestIEValueMethodRule(v KillRequestIEValue) aper.SourceRule { return v.rule() }
func BridgeKillResponseIEContainerValueCodecFieldCapture(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, aper.DecodeState) (KillResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEContainerValueCodecFieldCompare(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEContainerValueCodecFieldContext(v *KillResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEContainerValueCodecFieldDecode(v *KillResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEContainer, error) {
	return &v.decode
}
func BridgeKillResponseIEContainerValueCodecFieldEncode(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEContainerValueCodecFieldPath(v *KillResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEFieldFieldReplay(v *KillResponseIEField) *aper.Snapshot { return &v.replay }
func BridgeKillResponseIEFieldFieldWithoutReplay(v *KillResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEFieldMethodMarshalAPERTo(v *KillResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillResponseIEFieldMethodUnmarshalAPERFrom(v *KillResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillResponseIEFieldValueCodecFieldCapture(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, aper.DecodeState) (KillResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEFieldValueCodecFieldCompare(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEFieldValueCodecFieldContext(v *KillResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEFieldValueCodecFieldDecode(v *KillResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEField, error) {
	return &v.decode
}
func BridgeKillResponseIEFieldValueCodecFieldEncode(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEFieldValueCodecFieldPath(v *KillResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCapture(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, aper.DecodeState) (KillResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCompare(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldContext(v *KillResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldDecode(v *KillResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldEncode(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldPath(v *KillResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueFieldId(v *KillResponseIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeKillResponseIEValueFieldIsOpaque(v *KillResponseIEValue) *bool       { return &v.isOpaque }
func BridgeKillResponseIEValueFieldOpaque(v *KillResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeKillResponseIEValueFieldRowBroadcastCancelledAreaList(v *KillResponseIEValue) **BroadcastCancelledAreaList {
	return &v.rowBroadcastCancelledAreaList
}
func BridgeKillResponseIEValueFieldRowCriticalityDiagnostics(v *KillResponseIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeKillResponseIEValueFieldRowMessageIdentifier(v *KillResponseIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeKillResponseIEValueFieldRowSerialNumber(v *KillResponseIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeKillResponseIEValueMethodCaptureSemantics(v KillResponseIEValue, a0 aper.SemanticCapture) KillResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeKillResponseIEValueMethodCompareSemantics(v KillResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeKillResponseIEValueMethodMatchesID(v KillResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeKillResponseIEValueMethodRule(v KillResponseIEValue) aper.SourceRule { return v.rule() }
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *KillResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *KillResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBListValueCodecFieldCapture(v *RecommendedENBListValueCodec) *func(s40.RecommendedENBList, aper.DecodeState) (s40.RecommendedENBList, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBListValueCodecFieldCompare(v *RecommendedENBListValueCodec) *func(s40.RecommendedENBList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBListValueCodecFieldContext(v *RecommendedENBListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBListValueCodecFieldDecode(v *RecommendedENBListValueCodec) *func([]byte, aper.DecodeState) (s40.RecommendedENBList, error) {
	return &v.decode
}
func BridgeRecommendedENBListValueCodecFieldEncode(v *RecommendedENBListValueCodec) *func(s40.RecommendedENBList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBListValueCodecFieldPath(v *RecommendedENBListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBIDMethodMarshalAPERTo(v *SourceeNBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceeNBIDMethodUnmarshalAPERFrom(v *SourceeNBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBroadcastItemMethodMarshalAPERTo(v *TAIBroadcastItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBroadcastItemMethodUnmarshalAPERFrom(v *TAIBroadcastItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBroadcastValueCodecFieldCapture(v *TAIBroadcastValueCodec) *func(TAIBroadcast, aper.DecodeState) (TAIBroadcast, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBroadcastValueCodecFieldCompare(v *TAIBroadcastValueCodec) *func(TAIBroadcast, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBroadcastValueCodecFieldContext(v *TAIBroadcastValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBroadcastValueCodecFieldDecode(v *TAIBroadcastValueCodec) *func([]byte, aper.DecodeState) (TAIBroadcast, error) {
	return &v.decode
}
func BridgeTAIBroadcastValueCodecFieldEncode(v *TAIBroadcastValueCodec) *func(TAIBroadcast, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBroadcastValueCodecFieldPath(v *TAIBroadcastValueCodec) *aper.Path { return &v.path }
func BridgeTAICancelledItemMethodMarshalAPERTo(v *TAICancelledItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAICancelledItemMethodUnmarshalAPERFrom(v *TAICancelledItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAICancelledValueCodecFieldCapture(v *TAICancelledValueCodec) *func(TAICancelled, aper.DecodeState) (TAICancelled, aper.Snapshot) {
	return &v.capture
}
func BridgeTAICancelledValueCodecFieldCompare(v *TAICancelledValueCodec) *func(TAICancelled, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAICancelledValueCodecFieldContext(v *TAICancelledValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAICancelledValueCodecFieldDecode(v *TAICancelledValueCodec) *func([]byte, aper.DecodeState) (TAICancelled, error) {
	return &v.decode
}
func BridgeTAICancelledValueCodecFieldEncode(v *TAICancelledValueCodec) *func(TAICancelled, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAICancelledValueCodecFieldPath(v *TAICancelledValueCodec) *aper.Path { return &v.path }
func BridgeTAIListForRestartValueCodecFieldCapture(v *TAIListForRestartValueCodec) *func(TAIListForRestart, aper.DecodeState) (TAIListForRestart, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIListForRestartValueCodecFieldCompare(v *TAIListForRestartValueCodec) *func(TAIListForRestart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIListForRestartValueCodecFieldContext(v *TAIListForRestartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListForRestartValueCodecFieldDecode(v *TAIListForRestartValueCodec) *func([]byte, aper.DecodeState) (TAIListForRestart, error) {
	return &v.decode
}
func BridgeTAIListForRestartValueCodecFieldEncode(v *TAIListForRestartValueCodec) *func(TAIListForRestart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIListForRestartValueCodecFieldPath(v *TAIListForRestartValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIListforMDTValueCodecFieldCapture(v *TAIListforMDTValueCodec) *func(TAIListforMDT, aper.DecodeState) (TAIListforMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIListforMDTValueCodecFieldCompare(v *TAIListforMDTValueCodec) *func(TAIListforMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIListforMDTValueCodecFieldContext(v *TAIListforMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListforMDTValueCodecFieldDecode(v *TAIListforMDTValueCodec) *func([]byte, aper.DecodeState) (TAIListforMDT, error) {
	return &v.decode
}
func BridgeTAIListforMDTValueCodecFieldEncode(v *TAIListforMDTValueCodec) *func(TAIListforMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIListforMDTValueCodecFieldPath(v *TAIListforMDTValueCodec) *aper.Path { return &v.path }
func BridgeTAIListforQMCValueCodecFieldCapture(v *TAIListforQMCValueCodec) *func(TAIListforQMC, aper.DecodeState) (TAIListforQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIListforQMCValueCodecFieldCompare(v *TAIListforQMCValueCodec) *func(TAIListforQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIListforQMCValueCodecFieldContext(v *TAIListforQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListforQMCValueCodecFieldDecode(v *TAIListforQMCValueCodec) *func([]byte, aper.DecodeState) (TAIListforQMC, error) {
	return &v.decode
}
func BridgeTAIListforQMCValueCodecFieldEncode(v *TAIListforQMCValueCodec) *func(TAIListforQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIListforQMCValueCodecFieldPath(v *TAIListforQMCValueCodec) *aper.Path { return &v.path }
func BridgeTAIListforWarningValueCodecFieldCapture(v *TAIListforWarningValueCodec) *func(TAIListforWarning, aper.DecodeState) (TAIListforWarning, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIListforWarningValueCodecFieldCompare(v *TAIListforWarningValueCodec) *func(TAIListforWarning, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIListforWarningValueCodecFieldContext(v *TAIListforWarningValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListforWarningValueCodecFieldDecode(v *TAIListforWarningValueCodec) *func([]byte, aper.DecodeState) (TAIListforWarning, error) {
	return &v.decode
}
func BridgeTAIListforWarningValueCodecFieldEncode(v *TAIListforWarningValueCodec) *func(TAIListforWarning, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIListforWarningValueCodecFieldPath(v *TAIListforWarningValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIValueCodecFieldCapture(v *TAIValueCodec) *func(s40.TAI, aper.DecodeState) (s40.TAI, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIValueCodecFieldCompare(v *TAIValueCodec) *func(s40.TAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIValueCodecFieldContext(v *TAIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeTAIValueCodecFieldDecode(v *TAIValueCodec) *func([]byte, aper.DecodeState) (s40.TAI, error) {
	return &v.decode
}
func BridgeTAIValueCodecFieldEncode(v *TAIValueCodec) *func(s40.TAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIValueCodecFieldPath(v *TAIValueCodec) *aper.Path { return &v.path }
func BridgeUplinkNASTransportIEContainerValueCodecFieldCapture(v *UplinkNASTransportIEContainerValueCodec) *func(UplinkNASTransportIEContainer, aper.DecodeState) (UplinkNASTransportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportIEContainerValueCodecFieldCompare(v *UplinkNASTransportIEContainerValueCodec) *func(UplinkNASTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportIEContainerValueCodecFieldContext(v *UplinkNASTransportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(v *UplinkNASTransportIEContainerValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransportIEContainer, error) {
	return &v.decode
}
func BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(v *UplinkNASTransportIEContainerValueCodec) *func(UplinkNASTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportIEContainerValueCodecFieldPath(v *UplinkNASTransportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNASTransportIEFieldFieldReplay(v *UplinkNASTransportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkNASTransportIEFieldFieldWithoutReplay(v *UplinkNASTransportIEField) *bool {
	return &v.withoutReplay
}
func BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(v *UplinkNASTransportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(v *UplinkNASTransportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldCapture(v *UplinkNASTransportIEFieldValueCodec) *func(UplinkNASTransportIEField, aper.DecodeState) (UplinkNASTransportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldCompare(v *UplinkNASTransportIEFieldValueCodec) *func(UplinkNASTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldContext(v *UplinkNASTransportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldDecode(v *UplinkNASTransportIEFieldValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransportIEField, error) {
	return &v.decode
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldEncode(v *UplinkNASTransportIEFieldValueCodec) *func(UplinkNASTransportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportIEFieldValueCodecFieldPath(v *UplinkNASTransportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCapture(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *func(UplinkNASTransportIEValueERABIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCompare(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *func(UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldContext(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldDecode(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldEncode(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *func(UplinkNASTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldPath(v *UplinkNASTransportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNASTransportIEValueFieldId(v *UplinkNASTransportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUplinkNASTransportIEValueFieldIsOpaque(v *UplinkNASTransportIEValue) *bool {
	return &v.isOpaque
}
func BridgeUplinkNASTransportIEValueFieldOpaque(v *UplinkNASTransportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUplinkNASTransportIEValueFieldRowENBUES1APID(v *UplinkNASTransportIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUplinkNASTransportIEValueFieldRowEUTRANCGI(v *UplinkNASTransportIEValue) **s20.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeUplinkNASTransportIEValueFieldRowGWTransportLayerAddress(v *UplinkNASTransportIEValue) **s00.TransportLayerAddress {
	return &v.rowGWTransportLayerAddress
}
func BridgeUplinkNASTransportIEValueFieldRowLHNID(v *UplinkNASTransportIEValue) **s00.LHNID {
	return &v.rowLHNID
}
func BridgeUplinkNASTransportIEValueFieldRowLTENTNTAIInformation(v *UplinkNASTransportIEValue) **s22.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeUplinkNASTransportIEValueFieldRowMMEUES1APID(v *UplinkNASTransportIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUplinkNASTransportIEValueFieldRowNASPDU(v *UplinkNASTransportIEValue) **s00.NASPDU {
	return &v.rowNASPDU
}
func BridgeUplinkNASTransportIEValueFieldRowPSCellInformation(v *UplinkNASTransportIEValue) **s23.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgeUplinkNASTransportIEValueFieldRowSIPTOLGWTransportLayerAddress(v *UplinkNASTransportIEValue) **s00.TransportLayerAddress {
	return &v.rowSIPTOLGWTransportLayerAddress
}
func BridgeUplinkNASTransportIEValueFieldRowTAI(v *UplinkNASTransportIEValue) **s40.TAI {
	return &v.rowTAI
}
func BridgeUplinkNASTransportIEValueMethodCaptureSemantics(v UplinkNASTransportIEValue, a0 aper.SemanticCapture) UplinkNASTransportIEValue {
	return v.captureSemantics(a0)
}
func BridgeUplinkNASTransportIEValueMethodCompareSemantics(v UplinkNASTransportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUplinkNASTransportIEValueMethodMatchesID(v UplinkNASTransportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUplinkNASTransportIEValueMethodRule(v UplinkNASTransportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCapture(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolIEContainerList, aper.DecodeState) (UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCompare(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldContext(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldDecode(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldEncode(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(UplinkNASTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldPath(v *UplinkNASTransportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWarningAreaListFieldPerPadding(v *WarningAreaList) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWarningAreaListFieldReceived(v *WarningAreaList) *bool { return &v.received }
func BridgeWarningAreaListFieldReceivedBytes(v *WarningAreaList) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWarningAreaListFieldReceivedLocation(v *WarningAreaList) *aper.Location {
	return &v.receivedLocation
}
func BridgeWarningAreaListMethodMarshalAPERBudget(v *WarningAreaList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWarningAreaListMethodUnmarshalAPERFrom(v *WarningAreaList, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCapture(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCompare(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldContext(v *WriteReplaceWarningResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(v *WriteReplaceWarningResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldPath(v *WriteReplaceWarningResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v *WriteReplaceWarningResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v *WriteReplaceWarningResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(v *WriteReplaceWarningResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(v *WriteReplaceWarningResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCapture(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, aper.DecodeState) (WriteReplaceWarningResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCompare(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldContext(v *WriteReplaceWarningResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldDecode(v *WriteReplaceWarningResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEField, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldEncode(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldPath(v *WriteReplaceWarningResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueFieldId(v *WriteReplaceWarningResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWriteReplaceWarningResponseIEValueFieldIsOpaque(v *WriteReplaceWarningResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeWriteReplaceWarningResponseIEValueFieldOpaque(v *WriteReplaceWarningResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowBroadcastCompletedAreaList(v *WriteReplaceWarningResponseIEValue) **BroadcastCompletedAreaList {
	return &v.rowBroadcastCompletedAreaList
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowCriticalityDiagnostics(v *WriteReplaceWarningResponseIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowMessageIdentifier(v *WriteReplaceWarningResponseIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowSerialNumber(v *WriteReplaceWarningResponseIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeWriteReplaceWarningResponseIEValueMethodCaptureSemantics(v WriteReplaceWarningResponseIEValue, a0 aper.SemanticCapture) WriteReplaceWarningResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeWriteReplaceWarningResponseIEValueMethodCompareSemantics(v WriteReplaceWarningResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWriteReplaceWarningResponseIEValueMethodMatchesID(v WriteReplaceWarningResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeWriteReplaceWarningResponseIEValueMethodRule(v WriteReplaceWarningResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *KillRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 113:
		if value, ok := v.AsWarningAreaList(); ok {
			return value, true
		}
	case 191:
		if value, ok := v.AsKillAllWarningMessages(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *KillResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 141:
		if value, ok := v.AsBroadcastCancelledAreaList(); ok {
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
func (v *UplinkNASTransportIEValue) Selected() (any, bool) {
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
	case 26:
		if value, ok := v.AsNASPDU(); ok {
			return value, true
		}
	case 100:
		if value, ok := v.AsEUTRANCGI(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsTAI(); ok {
			return value, true
		}
	case 155:
		if value, ok := v.AsGWTransportLayerAddress(); ok {
			return value, true
		}
	case 184:
		if value, ok := v.AsSIPTOLGWTransportLayerAddress(); ok {
			return value, true
		}
	case 186:
		if value, ok := v.AsLHNID(); ok {
			return value, true
		}
	case 288:
		if value, ok := v.AsPSCellInformation(); ok {
			return value, true
		}
	case 339:
		if value, ok := v.AsLTENTNTAIInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *WriteReplaceWarningResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 120:
		if value, ok := v.AsBroadcastCompletedAreaList(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
