// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s10 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s10

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
)

// ErrorIndicationIEContainer is ProtocolIE-Container {{ErrorIndication-IEs}} of TS 36.455: a list of ErrorIndicationIEField values.
type ErrorIndicationIEContainer []ErrorIndicationIEField

// ErrorIndicationIEField is ProtocolIE-Field {{ErrorIndication-IEs}} of TS 36.455: a field carrying a value of ErrorIndicationIEValue.
type ErrorIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ErrorIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ErrorIndicationIEField) WithoutReplay() ErrorIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ErrorIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ErrorIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ErrorIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndicationIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ErrorIndicationIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationFailureIEContainer is ProtocolIE-Container {{OTDOAInformationFailure-IEs}} of TS 36.455: a list of OTDOAInformationFailureIEField values.
type OTDOAInformationFailureIEContainer []OTDOAInformationFailureIEField

// OTDOAInformationFailureIEField is ProtocolIE-Field {{OTDOAInformationFailure-IEs}} of TS 36.455: a field carrying a value of OTDOAInformationFailureIEValue.
type OTDOAInformationFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OTDOAInformationFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationFailureIEField) WithoutReplay() OTDOAInformationFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationFailureIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero OTDOAInformationFailureIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// UTDOAInformationResponseIEContainer is ProtocolIE-Container {{UTDOAInformationResponse-IEs}} of TS 36.455: a list of UTDOAInformationResponseIEField values.
type UTDOAInformationResponseIEContainer []UTDOAInformationResponseIEField

// UTDOAInformationResponseIEField is ProtocolIE-Field {{UTDOAInformationResponse-IEs}} of TS 36.455: a field carrying a value of UTDOAInformationResponseIEValue.
type UTDOAInformationResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UTDOAInformationResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationResponseIEField) WithoutReplay() UTDOAInformationResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *UTDOAInformationResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationResponseIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UTDOAInformationResponseIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// UTDOAInformationFailureIEContainer is ProtocolIE-Container {{UTDOAInformationFailure-IEs}} of TS 36.455: a list of UTDOAInformationFailureIEField values.
type UTDOAInformationFailureIEContainer []UTDOAInformationFailureIEField

// UTDOAInformationFailureIEField is ProtocolIE-Field {{UTDOAInformationFailure-IEs}} of TS 36.455: a field carrying a value of UTDOAInformationFailureIEValue.
type UTDOAInformationFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UTDOAInformationFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationFailureIEField) WithoutReplay() UTDOAInformationFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *UTDOAInformationFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationFailureIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UTDOAInformationFailureIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECIDMeasurementInitiationFailureMeasurementIDIEBinding binds MeasurementID to ProtocolIE-Field {{E-CIDMeasurementInitiationFailure-IEs}} of TS 36.455.
type ECIDMeasurementInitiationFailureMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) s09.ECIDMeasurementInitiationFailureIEValue

	get func(*s09.ECIDMeasurementInitiationFailureIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) New(value s00.MeasurementID,

) (s09.ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return s09.ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Get(field *s09.ECIDMeasurementInitiationFailureIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCauseIEBinding binds Cause to ProtocolIE-Field {{ErrorIndication-IEs}} of TS 36.455.
type ErrorIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s05.CauseValueCodec
	inject func(s05.Cause,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s05.Cause,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ErrorIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ErrorIndicationCauseIEBinding) Codec() s05.CauseValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ErrorIndicationCauseIEBinding) New(value s05.Cause,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ErrorIndicationCauseIEBinding) Get(field *ErrorIndicationIEField) (*s05.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{ErrorIndication-IEs}} of TS 36.455.
type ErrorIndicationCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Get(field *ErrorIndicationIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationFailureCauseIEBinding binds Cause to ProtocolIE-Field {{OTDOAInformationFailure-IEs}} of TS 36.455.
type OTDOAInformationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s05.CauseValueCodec
	inject func(s05.Cause,

	) OTDOAInformationFailureIEValue

	get func(*OTDOAInformationFailureIEValue,

	) (*s05.Cause,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationFailureCauseIEBinding) Codec() s05.CauseValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationFailureCauseIEBinding) New(value s05.Cause,

) (OTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationFailureCauseIEBinding) Get(field *OTDOAInformationFailureIEField) (*s05.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{OTDOAInformationFailure-IEs}} of TS 36.455.
type OTDOAInformationFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) OTDOAInformationFailureIEValue

	get func(*OTDOAInformationFailureIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (OTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Get(field *OTDOAInformationFailureIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationFailureCauseIEBinding binds Cause to ProtocolIE-Field {{UTDOAInformationFailure-IEs}} of TS 36.455.
type UTDOAInformationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s05.CauseValueCodec
	inject func(s05.Cause,

	) UTDOAInformationFailureIEValue

	get func(*UTDOAInformationFailureIEValue,

	) (*s05.Cause,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationFailureCauseIEBinding) Codec() s05.CauseValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationFailureCauseIEBinding) New(value s05.Cause,

) (UTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationFailureCauseIEBinding) Get(field *UTDOAInformationFailureIEField) (*s05.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{UTDOAInformationFailure-IEs}} of TS 36.455.
type UTDOAInformationFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) UTDOAInformationFailureIEValue

	get func(*UTDOAInformationFailureIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (UTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Get(field *UTDOAInformationFailureIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationResponseULConfigurationIEBinding binds ULConfiguration to ProtocolIE-Field {{UTDOAInformationResponse-IEs}} of TS 36.455.
type UTDOAInformationResponseULConfigurationIEBinding struct {
	info   s00.FieldInfo
	codec  ULConfigurationValueCodec
	inject func(ULConfiguration,

	) UTDOAInformationResponseIEValue

	get func(*UTDOAInformationResponseIEValue,

	) (*ULConfiguration,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationResponseULConfigurationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationResponseULConfigurationIEBinding) Codec() ULConfigurationValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationResponseULConfigurationIEBinding) New(value ULConfiguration,

) (UTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationResponseULConfigurationIEBinding) Get(field *UTDOAInformationResponseIEField) (*ULConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ULConfigurationValueCodec is the concrete ValueCodec[ULConfiguration].
type ULConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ULConfiguration, aper.DecodeState,

	) (ULConfiguration, aper.Snapshot,

	)
	compare func(ULConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ULConfiguration,

		error)
	encode func(ULConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ULConfigurationValueCodec) New(value ULConfiguration,

) (ULConfigurationAPERValue, error) {
	if c.encode == nil {
		return ULConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ULConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ULConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ULConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ULConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ULConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ULConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ULConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ULConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ULConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ULConfigurationValueCodec) EncodeAPER(value ULConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ULConfigurationValueCodec) encodeBudget(value ULConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ULConfigurationValueCodec) encodeChanged(value ULConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTDOAInformationResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{UTDOAInformationResponse-IEs}} of TS 36.455.
type UTDOAInformationResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) UTDOAInformationResponseIEValue

	get func(*UTDOAInformationResponseIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (UTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Get(field *UTDOAInformationResponseIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PosSIBsValueCodec is the concrete ValueCodec[PosSIBs].
type PosSIBsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PosSIBs, aper.DecodeState,

	) (PosSIBs, aper.Snapshot,

	)
	compare func(PosSIBs, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PosSIBs,

		error)
	encode func(PosSIBs,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PosSIBsValueCodec) New(value PosSIBs,

) (PosSIBsAPERValue, error) {
	if c.encode == nil {
		return PosSIBsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PosSIBsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PosSIBsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PosSIBsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PosSIBsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PosSIBsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PosSIBsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PosSIBsValueCodec) EncodeAPER(value PosSIBsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c PosSIBsValueCodec) encodeBudget(value PosSIBs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBsValueCodec) encodeChanged(value PosSIBs,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PosSIBsElemValueCodec is the concrete ValueCodec[PosSIBsElem].
type PosSIBsElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PosSIBsElem, aper.DecodeState,

	) (PosSIBsElem, aper.Snapshot,

	)
	compare func(PosSIBsElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PosSIBsElem,

		error)
	encode func(PosSIBsElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PosSIBsElemValueCodec) New(value PosSIBsElem,

) (PosSIBsElemAPERValue, error) {
	if c.encode == nil {
		return PosSIBsElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PosSIBsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PosSIBsElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PosSIBsElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PosSIBsElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PosSIBsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PosSIBsElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PosSIBsElemValueCodec) EncodeAPER(value PosSIBsElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c PosSIBsElemValueCodec) encodeBudget(value PosSIBsElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBsElemValueCodec) encodeChanged(value PosSIBsElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ULConfigurationAPERValue is the concrete APERValue[ULConfiguration].
type ULConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ULConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ULConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ULConfigurationAPERValue) WithoutReplay() ULConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBsAPERValue is the concrete APERValue[PosSIBs].
type PosSIBsAPERValue struct {
	context s00.BridgeCodecContext
	Value   PosSIBs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PosSIBsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBsAPERValue) WithoutReplay() PosSIBsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBsElemAPERValue is the concrete APERValue[PosSIBsElem].
type PosSIBsElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   PosSIBsElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PosSIBsElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBsElemAPERValue) WithoutReplay() PosSIBsElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type PosSIBs = []PosSIBsElem

// ULConfiguration represents the ASN.1 type ULConfiguration (SEQUENCE).
type ULConfiguration struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         aper.WireSpan
	Pci                   s00.PCI                         `asn1:"tag:0,context,implicit"`
	UlEarfcn              s00.EARFCN                      `asn1:"tag:1,context,implicit"`
	TimingAdvanceType1    *int64                          `asn1:"tag:2,context,implicit,optional" json:"TimingAdvanceType1,omitempty"`
	TimingAdvanceType2    *int64                          `asn1:"tag:3,context,implicit,optional" json:"TimingAdvanceType2,omitempty"`
	NumberOfTransmissions *big.Int                        `asn1:"tag:4,context,implicit"`
	SrsConfiguration      s09.SRSConfigurationForAllCells `asn1:"tag:5,context,implicit"`
	srsConfigurationIndef bool                            `asn1:"-" json:"-"`
	extCount              int64                           `asn1:"-" json:"-"`
	extPresent            []bool                          `asn1:"-" json:"-"`
	extData               [][]byte                        `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// PosSIBsElem represents the ASN.1 type PosSIBs-Elem (SEQUENCE).
type PosSIBsElem struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	withoutReplay                 bool
	received                      bool
	receivedBytes                 aper.WireSpan
	PosSIBType                    s00.PosSIBType                     `asn1:"tag:0,context,implicit"`
	PosSIBSegments                s08.PosSIBSegments                 `asn1:"tag:1,context,implicit"`
	posSIBSegmentsIndef           bool                               `asn1:"-" json:"-"`
	AssistanceInformationMetaData *s05.AssistanceInformationMetaData `asn1:"tag:2,context,implicit,optional" json:"AssistanceInformationMetaData,omitempty"`
	BroadcastPriority             *big.Int                           `asn1:"tag:3,context,implicit,optional" json:"BroadcastPriority,omitempty"`
	IEExtensions                  s04.PosSIBsExtIEsExtContainer      `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                               `asn1:"-" json:"-"`
	extCount                      int64                              `asn1:"-" json:"-"`
	extPresent                    []bool                             `asn1:"-" json:"-"`
	extData                       [][]byte                           `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}
type BridgeAsn1cAPERPosSIBsListValue struct{ Value PosSIBs }

// MarshalAPER encodes ULConfiguration to APER format.
func (v *ULConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ULConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.TimingAdvanceType1 != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TimingAdvanceType2 != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Pci, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
		return fmt.Errorf("encoding pci: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
		return fmt.Errorf("encoding ul-earfcn: %w", err)
	}
	if v.TimingAdvanceType1 != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType1), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding timingAdvanceType1: %w", err)
		}
	}
	if v.TimingAdvanceType2 != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType2), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding timingAdvanceType2: %w", err)
		}
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound16, true); err != nil {
		return fmt.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.SrsConfiguration)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_srsconfiguration < 0 || fragmentOffset_srsconfiguration > int64(len(v.SrsConfiguration)) || fragmentLength_srsconfiguration < 0 || fragmentLength_srsconfiguration > int64(len(v.SrsConfiguration[fragmentOffset_srsconfiguration:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SrsConfiguration[fragmentOffset_srsconfiguration : fragmentOffset_srsconfiguration+fragmentLength_srsconfiguration] {
			if err := s09.BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding srsConfiguration element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding srsConfiguration: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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

// UnmarshalAPER decodes ULConfiguration from APER format.
func (v *ULConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ULConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ULConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ULConfiguration")
	}
	bb.EnterComponent("ULConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "ULConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "ULConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ULConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ULConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_timingadvancetype1, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_timingadvancetype2, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Pci")
	}
	v.Pci = val_pci
	val_ulearfcn, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlEarfcn")
	}
	v.UlEarfcn = val_ulearfcn
	if opt_timingadvancetype1 {
		val_timingadvancetype1, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimingAdvanceType1")
		}
		if err := aper.ChargeValue(bb, val_timingadvancetype1); err != nil {
			return err
		}
		v.TimingAdvanceType1 = (*int64)(bb.OwnInt64(int64(val_timingadvancetype1)))
	}
	if opt_timingadvancetype2 {
		val_timingadvancetype2, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimingAdvanceType2")
		}
		if err := aper.ChargeValue(bb, val_timingadvancetype2); err != nil {
			return err
		}
		v.TimingAdvanceType2 = (*int64)(bb.OwnInt64(int64(val_timingadvancetype2)))
	}
	val_numberoftransmissions, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	toleranceMark_srsconfiguration := bb.EnterComponent("SrsConfiguration")
	v.SrsConfiguration = make(s09.SRSConfigurationForAllCells, 0)
	_, errCollection_srsconfiguration := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_srsconfiguration < 0 || fragmentLength_srsconfiguration < 0 || fragmentLength_srsconfiguration > int64(^uint(0)>>1) || fragmentOffset_srsconfiguration > int64(^uint(0)>>1)-fragmentLength_srsconfiguration {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_srsconfiguration; i++ {
			var elem s09.SRSConfigurationForOneCell
			elementMark := bb.EnterIndex(fragmentOffset_srsconfiguration + i)
			if err := s09.BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SrsConfiguration[%d]", fragmentOffset_srsconfiguration+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.SrsConfiguration, elem); err != nil {
				return err
			} else {
				v.SrsConfiguration = next
			}
		}
		return nil
	})
	if errCollection_srsconfiguration != nil {
		return runtime.WrapDecodePath(errCollection_srsconfiguration, "SrsConfiguration")
	}
	bb.LeaveComponent(toleranceMark_srsconfiguration)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes PosSIBsElem to APER format.
func (v *PosSIBsElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PosSIBsElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.AssistanceInformationMetaData != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.BroadcastPriority != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return fmt.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.PosSIBSegments)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_possibsegments < 0 || fragmentOffset_possibsegments > int64(len(v.PosSIBSegments)) || fragmentLength_possibsegments < 0 || fragmentLength_possibsegments > int64(len(v.PosSIBSegments[fragmentOffset_possibsegments:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PosSIBSegments[fragmentOffset_possibsegments : fragmentOffset_possibsegments+fragmentLength_possibsegments] {
			if err := s08.BridgePosSIBSegmentsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding posSIB-Segments element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding posSIB-Segments: %w", err)
	}
	if v.AssistanceInformationMetaData != nil {
		if err := s05.BridgeAssistanceInformationMetaDataMethodMarshalAPERTo(v.AssistanceInformationMetaData, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding assistanceInformationMetaData: %w", err)
		}
	}
	if v.BroadcastPriority != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.BroadcastPriority, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound8, true); err != nil {
			return fmt.Errorf("encoding broadcastPriority: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgePosSIBsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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

// UnmarshalAPER decodes PosSIBsElem from APER format.
func (v *PosSIBsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBsElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBsElem")
	}
	bb.EnterComponent("PosSIBsElem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBsElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "PosSIBsElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PosSIBsElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsElem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_assistanceinformationmetadata, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_broadcastpriority, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_possibtype, err := aper.DecodeEnumeratedAligned(bb, 27, true, aper.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = s00.PosSIBType(val_possibtype)
	toleranceMark_possibsegments := bb.EnterComponent("PosSIBSegments")
	v.PosSIBSegments = make(s08.PosSIBSegments, 0)
	_, errCollection_possibsegments := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_possibsegments < 0 || fragmentLength_possibsegments < 0 || fragmentLength_possibsegments > int64(^uint(0)>>1) || fragmentOffset_possibsegments > int64(^uint(0)>>1)-fragmentLength_possibsegments {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_possibsegments; i++ {
			var elem s08.PosSIBSegmentsElem
			elementMark := bb.EnterIndex(fragmentOffset_possibsegments + i)
			if err := s08.BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBSegments[%d]", fragmentOffset_possibsegments+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.PosSIBSegments, elem); err != nil {
				return err
			} else {
				v.PosSIBSegments = next
			}
		}
		return nil
	})
	if errCollection_possibsegments != nil {
		return runtime.WrapDecodePath(errCollection_possibsegments, "PosSIBSegments")
	}
	bb.LeaveComponent(toleranceMark_possibsegments)
	if opt_assistanceinformationmetadata {
		toleranceMark_assistanceinformationmetadata := bb.EnterComponent("AssistanceInformationMetaData")
		var dec_assistanceinformationmetadata s05.AssistanceInformationMetaData
		if err := s05.BridgeAssistanceInformationMetaDataMethodUnmarshalAPERFrom(&dec_assistanceinformationmetadata, bb); err != nil {
			return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
		}
		if err := aper.ChargeValue(bb, dec_assistanceinformationmetadata); err != nil {
			return err
		}
		v.AssistanceInformationMetaData = &dec_assistanceinformationmetadata
		bb.LeaveComponent(toleranceMark_assistanceinformationmetadata)
	}
	if opt_broadcastpriority {
		val_broadcastpriority, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "BroadcastPriority")
		}
		v.BroadcastPriority = val_broadcastpriority
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.PosSIBsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.PosSIBsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgePosSIBsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBsElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBsElem) WithoutReplay() PosSIBsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PosSIBsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ULConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULConfiguration) WithoutReplay() ULConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ULConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PosSIBsElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PosSIBsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PosSIBsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ULConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ULConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ULConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *PosSIBsElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PosSIBsElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PosSIBsElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PosSIBsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PosSIBsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PosSIBsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PosSIBsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PosSIBsElem")
}
func (v *PosSIBsElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBsElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBsElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaPosSIBsElem(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBsElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBsElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ULConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ULConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ULConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaULConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ULConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ULConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ULConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ULConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ULConfiguration")
}
func (v *ULConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ULConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ULConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaULConfiguration(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ULConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ULConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBsElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PosSIBsElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBsElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBsElem{}
		return report, aper.OperationError(err, "PosSIBsElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PosSIBsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ULConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ULConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ULConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaULConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ULConfiguration{}
		return report, aper.OperationError(err, "ULConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ULConfiguration")
}
func BridgeCaptureLPPaErrorIndicationIEValue(v *ErrorIndicationIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ErrorIndicationIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ErrorIndicationIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ErrorIndicationIEValue) captureSemantics(s aper.SemanticCapture) ErrorIndicationIEValue {
	BridgeCaptureLPPaErrorIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaErrorIndicationIEValue(v *ErrorIndicationIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ErrorIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaErrorIndicationIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ErrorIndicationIEValue) WithoutReplay() ErrorIndicationIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaMBSFNsubframeConfiguration(v *s09.MBSFNsubframeConfiguration, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			s09.BridgeCompareLPPaMBSFNsubframeConfigurationValue(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOAInformationFailureIEValue(v *OTDOAInformationFailureIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationFailureIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOAInformationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationFailureIEValue) captureSemantics(s aper.SemanticCapture) OTDOAInformationFailureIEValue {
	BridgeCaptureLPPaOTDOAInformationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationFailureIEValue(v *OTDOAInformationFailureIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationFailureIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationFailureIEValue) WithoutReplay() OTDOAInformationFailureIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaPosSIBSegments(v *s08.PosSIBSegments, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			s08.BridgeCompareLPPaPosSIBSegmentsElem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaPosSIBs(v *PosSIBs, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaPosSIBsElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaPosSIBs(v *PosSIBs, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaPosSIBsElem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaPosSIBsElem(v *PosSIBsElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPosSIBType(&v.PosSIBType, s)
	s09.BridgeCaptureLPPaPosSIBSegments(&v.PosSIBSegments, s)
	{
		f := s.Begin()
		s.Bool(v.AssistanceInformationMetaData == nil)
		if v.AssistanceInformationMetaData != nil {
			s05.BridgeCaptureLPPaAssistanceInformationMetaData(v.AssistanceInformationMetaData, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.BroadcastPriority)
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s05.BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBsElem(v *PosSIBsElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPosSIBType(&v.PosSIBType, s)
	BridgeCompareLPPaPosSIBSegments(&v.PosSIBSegments, s)
	{
		f := s.Begin()
		s.Bool(v.AssistanceInformationMetaData == nil)
		if v.AssistanceInformationMetaData != nil {
			s05.BridgeCompareLPPaAssistanceInformationMetaData(v.AssistanceInformationMetaData, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.BroadcastPriority)
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s05.BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForAllCells(v *s09.SRSConfigurationForAllCells, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			s09.BridgeCompareLPPaSRSConfigurationForOneCell(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaULConfiguration(v *ULConfiguration, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPCI(&v.Pci, s)
	s00.BridgeCaptureLPPaEARFCN(&v.UlEarfcn, s)
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType1 == nil)
		if v.TimingAdvanceType1 != nil {
			s.Int(int64((*v.TimingAdvanceType1)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType2 == nil)
		if v.TimingAdvanceType2 != nil {
			s.Int(int64((*v.TimingAdvanceType2)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, nil, false)
	}
	s09.BridgeCaptureLPPaSRSConfigurationForAllCells(&v.SrsConfiguration, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaULConfiguration(v *ULConfiguration, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPCI(&v.Pci, s)
	s02.BridgeCompareLPPaEARFCN(&v.UlEarfcn, s)
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType1 == nil)
		if v.TimingAdvanceType1 != nil {
			s.Int(int64((*v.TimingAdvanceType1)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType2 == nil)
		if v.TimingAdvanceType2 != nil {
			s.Int(int64((*v.TimingAdvanceType2)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, aper.Snapshot{}, false)
	}
	BridgeCompareLPPaSRSConfigurationForAllCells(&v.SrsConfiguration, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationFailureIEValue(v *UTDOAInformationFailureIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationFailureIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v UTDOAInformationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationFailureIEValue) captureSemantics(s aper.SemanticCapture) UTDOAInformationFailureIEValue {
	BridgeCaptureLPPaUTDOAInformationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationFailureIEValue(v *UTDOAInformationFailureIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationFailureIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationFailureIEValue) WithoutReplay() UTDOAInformationFailureIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaUTDOAInformationResponseIEValue(v *UTDOAInformationResponseIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					BridgeCaptureLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationResponseIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v UTDOAInformationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationResponseIEValue) captureSemantics(s aper.SemanticCapture) UTDOAInformationResponseIEValue {
	BridgeCaptureLPPaUTDOAInformationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationResponseIEValue(v *UTDOAInformationResponseIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					BridgeCompareLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationResponseIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationResponseIEValue) WithoutReplay() UTDOAInformationResponseIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type ErrorIndicationIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s05.Cause
	rowCriticalityDiagnostics *s09.CriticalityDiagnostics
}

func (v ErrorIndicationIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowCause != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ErrorIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ErrorIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs"}}
}
func (ErrorIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	default:
		return aper.UnknownSelector
	}
}

// AsCause returns the selected Cause value and reports whether that alternative is active.
func (v *ErrorIndicationIEValue) AsCause() (*s05.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *ErrorIndicationIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ErrorIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	out := ErrorIndicationIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value s05.Cause
		child := raw.ChildDecodeBuffer()
		if err := s05.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s05.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s05.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s05.BridgeCauseFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ErrorIndicationIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ErrorIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "ErrorIndication-IEs.id-Cause:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s05.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "ErrorIndication-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ErrorIndicationIEValue:", v.id)
	}
}

type OTDOAInformationFailureIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s05.Cause
	rowCriticalityDiagnostics *s09.CriticalityDiagnostics
}

func (v OTDOAInformationFailureIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowCause != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOAInformationFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs"}}
}
func (OTDOAInformationFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	default:
		return aper.UnknownSelector
	}
}

// AsCause returns the selected Cause value and reports whether that alternative is active.
func (v *OTDOAInformationFailureIEValue) AsCause() (*s05.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *OTDOAInformationFailureIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v OTDOAInformationFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOAInformationFailureIEValue, error) {
	out := OTDOAInformationFailureIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value s05.Cause
		child := raw.ChildDecodeBuffer()
		if err := s05.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s05.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s05.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s05.BridgeCauseFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v OTDOAInformationFailureIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationFailure-IEs.id-Cause:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s05.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOAInformationFailureIEValue:", v.id)
	}
}

type UTDOAInformationFailureIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *s05.Cause
	rowCriticalityDiagnostics *s09.CriticalityDiagnostics
}

func (v UTDOAInformationFailureIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowCause != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *UTDOAInformationFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs"}}
}
func (UTDOAInformationFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	default:
		return aper.UnknownSelector
	}
}

// AsCause returns the selected Cause value and reports whether that alternative is active.
func (v *UTDOAInformationFailureIEValue) AsCause() (*s05.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *UTDOAInformationFailureIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UTDOAInformationFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UTDOAInformationFailureIEValue, error) {
	out := UTDOAInformationFailureIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value s05.Cause
		child := raw.ChildDecodeBuffer()
		if err := s05.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s05.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s05.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s05.BridgeCauseFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v UTDOAInformationFailureIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationFailure-IEs.id-Cause:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s05.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UTDOAInformationFailureIEValue:", v.id)
	}
}

type UTDOAInformationResponseIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowULConfiguration        *ULConfiguration
	rowCriticalityDiagnostics *s09.CriticalityDiagnostics
}

func (v UTDOAInformationResponseIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(13):
		return v.rowULConfiguration != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *UTDOAInformationResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs"}}
}
func (UTDOAInformationResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(13):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
		return aper.NotInTable
	case s00.ProtocolIEID(12):
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
	default:
		return aper.UnknownSelector
	}
}

// AsULConfiguration returns the selected ULConfiguration value and reports whether that alternative is active.
func (v *UTDOAInformationResponseIEValue) AsULConfiguration() (*ULConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(13) || v.rowULConfiguration == nil {
		return nil, false
	}
	return v.rowULConfiguration, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *UTDOAInformationResponseIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UTDOAInformationResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UTDOAInformationResponseIEValue, error) {
	out := UTDOAInformationResponseIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 13, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(13):
		replayUsage := scope.Usage()
		var value ULConfiguration
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ULConfiguration")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowULConfiguration = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v UTDOAInformationResponseIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(13):
		if v.rowULConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationResponse-IEs.id-ULConfiguration:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowULConfiguration.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UTDOAInformationResponseIEValue:", v.id)
	}
}

type ECIDMeasurementInitiationFailureIETable struct{}

func ECIDMeasurementInitiationFailureIEs() ECIDMeasurementInitiationFailureIETable {
	return ECIDMeasurementInitiationFailureIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementInitiationFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationFailureIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementInitiationFailureIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationFailureMeasurementIDIEBinding {
	return ECIDMeasurementInitiationFailureMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero s09.ECIDMeasurementInitiationFailureIEValue
			decoded, err := s09.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s09.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() s09.ECIDMeasurementInitiationFailureIEValue {
				sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) s09.ECIDMeasurementInitiationFailureIEValue {
			return func() s09.ECIDMeasurementInitiationFailureIEValue {
				sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s09.ECIDMeasurementInitiationFailureIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of this table.
func (t ECIDMeasurementInitiationFailureIETable) Cause() s09.ECIDMeasurementInitiationFailureCauseIEBinding {
	return func() s09.ECIDMeasurementInitiationFailureCauseIEBinding {
		sealed := s09.ECIDMeasurementInitiationFailureCauseIEBinding{}
		*s09.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInfo(&sealed) = t.infoCause()
		*s09.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldCodec(&sealed) = func() s05.CauseValueCodec {
			sealed := s05.CauseValueCodec{}
			*s05.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
			*s05.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.Cause, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s05.Cause
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cause")
				var zero s09.ECIDMeasurementInitiationFailureIEValue
				decoded, err := s09.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s05.Cause
					return empty, runtime.WrapDecodePath(err, "Cause")
				}
				value, ok := decoded.AsCause()
				if !ok {
					var empty s05.Cause
					return empty, fmt.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-Cause: no selected value")
				}
				return *value, nil
			}
			*s05.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s05.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s09.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() s09.ECIDMeasurementInitiationFailureIEValue {
					sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
					*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s05.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s05.Cause, options aper.DecodeState) (s05.Cause, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s05.BridgeCaptureLPPaCause(&v, &s)
				var root aper.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*s05.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s05.Cause, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
				s := aper.NewSemanticComparison(root,
					limits)
				f := s.Begin()
				s05.BridgeCompareLPPaCause(&v, &s)
				s.End(
					f, root, false)
				return s.Plan()
			}
			*s05.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
				return sealed
			}()
			return sealed
		}()
		*s09.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInject(&sealed) = func(value s05.Cause) s09.ECIDMeasurementInitiationFailureIEValue {
			return func() s09.ECIDMeasurementInitiationFailureIEValue {
				sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(&sealed) = &value
				return sealed
			}()
		}
		*s09.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldGet(&sealed) = func(value *s09.ECIDMeasurementInitiationFailureIEValue) (*s05.Cause, bool) { return value.AsCause() }
		return sealed
	}()
}
func (ECIDMeasurementInitiationFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t ECIDMeasurementInitiationFailureIETable) CriticalityDiagnostics() s09.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding {
	return func() s09.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding {
		sealed := s09.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding{}
		*s09.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s09.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s09.CriticalityDiagnosticsValueCodec {
			sealed := s09.CriticalityDiagnosticsValueCodec{}
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s09.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s09.ECIDMeasurementInitiationFailureIEValue
				decoded, err := s09.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, s00.ProtocolIEID(1), raw)
				if err != nil {
					var empty s09.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s09.CriticalityDiagnostics
					return empty, fmt.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s09.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() s09.ECIDMeasurementInitiationFailureIEValue {
					sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
					*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
					*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
				s := aper.NewSemanticComparison(root, limits)
				f := s.Begin()
				s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan()
			}
			*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				return sealed
			}()
			return sealed
		}()
		*s09.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s09.CriticalityDiagnostics) s09.ECIDMeasurementInitiationFailureIEValue {
			return func() s09.ECIDMeasurementInitiationFailureIEValue {
				sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s09.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s09.ECIDMeasurementInitiationFailureIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementInitiationFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s09.ECIDMeasurementInitiationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(0):
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return s09.ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return s09.ECIDMeasurementInitiationFailureIEField{Id: id, Criticality: criticality, Value: func() s09.ECIDMeasurementInitiationFailureIEValue {
			sealed := s09.ECIDMeasurementInitiationFailureIEValue{}
			*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = id
			*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldOpaque(&sealed) = retained
			*s09.BridgeECIDMeasurementInitiationFailureIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ErrorIndicationIETable struct{}

func ErrorIndicationIEs() ErrorIndicationIETable { return ErrorIndicationIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ErrorIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs"}
		return sealed
	}()
}
func (ErrorIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of this table.
func (t ErrorIndicationIETable) Cause() ErrorIndicationCauseIEBinding {
	return ErrorIndicationCauseIEBinding{info: t.infoCause(), codec: func() s05.CauseValueCodec {
		sealed := s05.CauseValueCodec{}
		*s05.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s05.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s05.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s05.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s05.Cause
				return empty, fmt.Errorf("binding ErrorIndication-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s05.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s05.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s05.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s05.Cause, options aper.DecodeState) (s05.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s05.BridgeCaptureLPPaCause(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s05.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s05.Cause, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s05.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s05.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s05.Cause) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s05.Cause, bool) { return value.AsCause() }}
}
func (ErrorIndicationIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t ErrorIndicationIETable) CriticalityDiagnostics() ErrorIndicationCriticalityDiagnosticsIEBinding {
	return ErrorIndicationCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding ErrorIndication-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ErrorIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ErrorIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ErrorIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ErrorIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ErrorIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ErrorIndicationIEField{Id: id, Criticality: criticality, Value: ErrorIndicationIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationFailureIETable struct{}

func OTDOAInformationFailureIEs() OTDOAInformationFailureIETable {
	return OTDOAInformationFailureIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOAInformationFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs"}
		return sealed
	}()
}
func (OTDOAInformationFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of this table.
func (t OTDOAInformationFailureIETable) Cause() OTDOAInformationFailureCauseIEBinding {
	return OTDOAInformationFailureCauseIEBinding{info: t.infoCause(), codec: func() s05.CauseValueCodec {
		sealed := s05.CauseValueCodec{}
		*s05.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s05.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s05.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero OTDOAInformationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s05.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s05.Cause
				return empty, fmt.Errorf("binding OTDOAInformationFailure-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s05.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s05.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationFailureIEValue{id: s00.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s05.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s05.Cause, options aper.DecodeState) (s05.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s05.BridgeCaptureLPPaCause(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s05.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s05.Cause, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s05.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s05.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s05.Cause) OTDOAInformationFailureIEValue {
			return OTDOAInformationFailureIEValue{id: s00.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *OTDOAInformationFailureIEValue) (*s05.Cause, bool) { return value.AsCause() }}
}
func (OTDOAInformationFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationFailureIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t OTDOAInformationFailureIETable) CriticalityDiagnostics() OTDOAInformationFailureCriticalityDiagnosticsIEBinding {
	return OTDOAInformationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero OTDOAInformationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding OTDOAInformationFailure-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationFailureIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) OTDOAInformationFailureIEValue {
			return OTDOAInformationFailureIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *OTDOAInformationFailureIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOAInformationFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOAInformationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return OTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOAInformationFailureIEField{Id: id, Criticality: criticality, Value: OTDOAInformationFailureIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UTDOAInformationFailureIETable struct{}

func UTDOAInformationFailureIEs() UTDOAInformationFailureIETable {
	return UTDOAInformationFailureIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (UTDOAInformationFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs"}
		return sealed
	}()
}
func (UTDOAInformationFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of this table.
func (t UTDOAInformationFailureIETable) Cause() UTDOAInformationFailureCauseIEBinding {
	return UTDOAInformationFailureCauseIEBinding{info: t.infoCause(), codec: func() s05.CauseValueCodec {
		sealed := s05.CauseValueCodec{}
		*s05.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s05.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s05.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero UTDOAInformationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s05.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s05.Cause
				return empty, fmt.Errorf("binding UTDOAInformationFailure-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s05.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s05.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationFailureIEValue{id: s00.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s05.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s05.Cause, options aper.DecodeState) (s05.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s05.BridgeCaptureLPPaCause(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s05.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s05.Cause, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s05.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s05.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s05.Cause) UTDOAInformationFailureIEValue {
			return UTDOAInformationFailureIEValue{id: s00.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *UTDOAInformationFailureIEValue) (*s05.Cause, bool) { return value.AsCause() }}
}
func (UTDOAInformationFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationFailureIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t UTDOAInformationFailureIETable) CriticalityDiagnostics() UTDOAInformationFailureCriticalityDiagnosticsIEBinding {
	return UTDOAInformationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero UTDOAInformationFailureIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UTDOAInformationFailure-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationFailureIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) UTDOAInformationFailureIEValue {
			return UTDOAInformationFailureIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *UTDOAInformationFailureIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t UTDOAInformationFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UTDOAInformationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return UTDOAInformationFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return UTDOAInformationFailureIEField{Id: id, Criticality: criticality, Value: UTDOAInformationFailureIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UTDOAInformationResponseIETable struct{}

func UTDOAInformationResponseIEs() UTDOAInformationResponseIETable {
	return UTDOAInformationResponseIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (UTDOAInformationResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs"}
		return sealed
	}()
}
func (UTDOAInformationResponseIETable) infoULConfiguration() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationResponseIEs().ID(), ID: s00.ProtocolIEID(13), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ULConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs", Row: "id-ULConfiguration"}}}
}

// ULConfiguration returns the typed binding for the ULConfiguration row of this table.
func (t UTDOAInformationResponseIETable) ULConfiguration() UTDOAInformationResponseULConfigurationIEBinding {
	return UTDOAInformationResponseULConfigurationIEBinding{info: t.infoULConfiguration(), codec: ULConfigurationValueCodec{path: "ULConfiguration",
		decode: func(data []byte, options aper.DecodeState) (ULConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ULConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ULConfiguration")
			var zero UTDOAInformationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(13), raw)
			if err != nil {
				var empty ULConfiguration
				return empty, runtime.WrapDecodePath(err, "ULConfiguration")
			}
			value, ok := decoded.AsULConfiguration()
			if !ok {
				var empty ULConfiguration
				return empty, fmt.Errorf("binding UTDOAInformationResponse-IEs.id-ULConfiguration: no selected value")
			}
			return *value, nil
		},
		encode: func(value ULConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationResponseIEValue{id: s00.ProtocolIEID(13), rowULConfiguration: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ULConfiguration, options aper.DecodeState) (ULConfiguration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaULConfiguration(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ULConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaULConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULConfiguration"
			return sealed
		}(),
	}, inject: func(value ULConfiguration) UTDOAInformationResponseIEValue {
		return UTDOAInformationResponseIEValue{id: s00.ProtocolIEID(13), rowULConfiguration: &value}
	}, get: func(value *UTDOAInformationResponseIEValue) (*ULConfiguration, bool) {
		return value.AsULConfiguration()
	}}
}
func (UTDOAInformationResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationResponseIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t UTDOAInformationResponseIETable) CriticalityDiagnostics() UTDOAInformationResponseCriticalityDiagnosticsIEBinding {
	return UTDOAInformationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero UTDOAInformationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UTDOAInformationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) UTDOAInformationResponseIEValue {
			return UTDOAInformationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *UTDOAInformationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t UTDOAInformationResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UTDOAInformationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(13):
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-ULConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return UTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UTDOAInformationResponseIEField{Id: id, Criticality: criticality, Value: UTDOAInformationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// PosSIBsElemCodec binds the complete source value type.
func PosSIBsElemCodec() PosSIBsElemValueCodec {
	return PosSIBsElemValueCodec{path: "PosSIBsElem", decode: func(data []byte, options aper.DecodeState) (PosSIBsElem, error) {
		var value PosSIBsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PosSIBsElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PosSIBsElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PosSIBsElem, options aper.DecodeState) (PosSIBsElem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPosSIBsElem(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PosSIBsElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPosSIBsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBsElem"
		return sealed
	}(),
	}
}

// ULConfigurationCodec binds the complete APER value type.
func ULConfigurationCodec() ULConfigurationValueCodec {
	return UTDOAInformationResponseIEs().ULConfiguration().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ErrorIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if v.rowCause != nil {
			return v.rowCause, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OTDOAInformationFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if v.rowCause != nil {
			return v.rowCause, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UTDOAInformationFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if v.rowCause != nil {
			return v.rowCause, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UTDOAInformationResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 13:
		if v.rowULConfiguration != nil {
			return v.rowULConfiguration, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	}
	return nil, false
}

func BridgeECIDMeasurementInitiationFailureIETableMethodInfoCause(v ECIDMeasurementInitiationFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeECIDMeasurementInitiationFailureIETableMethodInfoCriticalityDiagnostics(v ECIDMeasurementInitiationFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeECIDMeasurementInitiationFailureIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationFailureIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *func(*s09.ECIDMeasurementInitiationFailureIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *func(s00.MeasurementID) s09.ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeErrorIndicationCauseIEBindingFieldCodec(v *ErrorIndicationCauseIEBinding) *s05.CauseValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCauseIEBindingFieldGet(v *ErrorIndicationCauseIEBinding) *func(*ErrorIndicationIEValue) (*s05.Cause, bool) {
	return &v.get
}
func BridgeErrorIndicationCauseIEBindingFieldInfo(v *ErrorIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCauseIEBindingFieldInject(v *ErrorIndicationCauseIEBinding) *func(s05.Cause) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldCodec(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldGet(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(*ErrorIndicationIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInfo(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInject(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationIEFieldFieldReceived(v *ErrorIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeErrorIndicationIEFieldFieldReplay(v *ErrorIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEFieldFieldStream(v *ErrorIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeErrorIndicationIEFieldFieldWithoutReplay(v *ErrorIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEFieldMethodMarshalAPERTo(v *ErrorIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationIEFieldMethodUnmarshalAPERFrom(v *ErrorIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationIETableMethodInfoCause(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeErrorIndicationIETableMethodInfoCriticalityDiagnostics(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeErrorIndicationIEValueFieldId(v *ErrorIndicationIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeErrorIndicationIEValueFieldIsOpaque(v *ErrorIndicationIEValue) *bool       { return &v.isOpaque }
func BridgeErrorIndicationIEValueFieldOpaque(v *ErrorIndicationIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeErrorIndicationIEValueFieldReceived(v *ErrorIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueFieldReplay(v *ErrorIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueFieldRowCause(v *ErrorIndicationIEValue) **s05.Cause {
	return &v.rowCause
}
func BridgeErrorIndicationIEValueFieldRowCriticalityDiagnostics(v *ErrorIndicationIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeErrorIndicationIEValueFieldWithoutReplay(v *ErrorIndicationIEValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEValueMethodCaptureFraming(v ErrorIndicationIEValue) uint64 {
	return v.captureFraming()
}
func BridgeErrorIndicationIEValueMethodCaptureSemantics(v ErrorIndicationIEValue, a0 aper.SemanticCapture) ErrorIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodCaptureSnapshot(v ErrorIndicationIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeErrorIndicationIEValueMethodCompareSemantics(v ErrorIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodDecode(v ErrorIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeErrorIndicationIEValueMethodEncode(v ErrorIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeErrorIndicationIEValueMethodEncodeFresh(v ErrorIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeErrorIndicationIEValueMethodMatchesID(v ErrorIndicationIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeErrorIndicationIEValueMethodReason(v ErrorIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeErrorIndicationIEValueMethodRule(v ErrorIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldCodec(v *OTDOAInformationFailureCauseIEBinding) *s05.CauseValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldGet(v *OTDOAInformationFailureCauseIEBinding) *func(*OTDOAInformationFailureIEValue) (*s05.Cause, bool) {
	return &v.get
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldInfo(v *OTDOAInformationFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldInject(v *OTDOAInformationFailureCauseIEBinding) *func(s05.Cause) OTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldGet(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(*OTDOAInformationFailureIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInject(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) OTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureIEFieldFieldReceived(v *OTDOAInformationFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationFailureIEFieldFieldReplay(v *OTDOAInformationFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureIEFieldFieldStream(v *OTDOAInformationFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v *OTDOAInformationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureIEFieldMethodMarshalAPERTo(v *OTDOAInformationFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationFailureIETableMethodInfoCause(v OTDOAInformationFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeOTDOAInformationFailureIETableMethodInfoCriticalityDiagnostics(v OTDOAInformationFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeOTDOAInformationFailureIEValueFieldId(v *OTDOAInformationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationFailureIEValueFieldIsOpaque(v *OTDOAInformationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationFailureIEValueFieldOpaque(v *OTDOAInformationFailureIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationFailureIEValueFieldReceived(v *OTDOAInformationFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationFailureIEValueFieldReplay(v *OTDOAInformationFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureIEValueFieldRowCause(v *OTDOAInformationFailureIEValue) **s05.Cause {
	return &v.rowCause
}
func BridgeOTDOAInformationFailureIEValueFieldRowCriticalityDiagnostics(v *OTDOAInformationFailureIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeOTDOAInformationFailureIEValueFieldWithoutReplay(v *OTDOAInformationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureFraming(v OTDOAInformationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureSemantics(v OTDOAInformationFailureIEValue, a0 aper.SemanticCapture) OTDOAInformationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureSnapshot(v OTDOAInformationFailureIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationFailureIEValueMethodCompareSemantics(v OTDOAInformationFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodDecode(v OTDOAInformationFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOAInformationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodEncode(v OTDOAInformationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationFailureIEValueMethodEncodeFresh(v OTDOAInformationFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodMatchesID(v OTDOAInformationFailureIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodReason(v OTDOAInformationFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodRule(v OTDOAInformationFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePosSIBsAPERValueFieldContext(v *PosSIBsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsAPERValueFieldReceived(v *PosSIBsAPERValue) *aper.WireSpan { return &v.received }
func BridgePosSIBsAPERValueFieldReplay(v *PosSIBsAPERValue) *aper.Snapshot   { return &v.replay }
func BridgePosSIBsAPERValueFieldWithoutReplay(v *PosSIBsAPERValue) *bool     { return &v.withoutReplay }
func BridgePosSIBsElemAPERValueFieldContext(v *PosSIBsElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsElemAPERValueFieldReceived(v *PosSIBsElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePosSIBsElemAPERValueFieldReplay(v *PosSIBsElemAPERValue) *aper.Snapshot { return &v.replay }
func BridgePosSIBsElemAPERValueFieldWithoutReplay(v *PosSIBsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsElemFieldExtCount(v *PosSIBsElem) *int64                { return &v.extCount }
func BridgePosSIBsElemFieldExtData(v *PosSIBsElem) *[][]byte              { return &v.extData }
func BridgePosSIBsElemFieldExtOrigin(v *PosSIBsElem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgePosSIBsElemFieldExtPresent(v *PosSIBsElem) *[]bool             { return &v.extPresent }
func BridgePosSIBsElemFieldExtWire(v *PosSIBsElem) *[]aper.WireSpan       { return &v.extWire }
func BridgePosSIBsElemFieldIEExtensionsIndef(v *PosSIBsElem) *bool        { return &v.iEExtensionsIndef }
func BridgePosSIBsElemFieldPerExtPadding(v *PosSIBsElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePosSIBsElemFieldPerPadding(v *PosSIBsElem) *aper.FinalPadding { return &v.perPadding }
func BridgePosSIBsElemFieldPosSIBSegmentsIndef(v *PosSIBsElem) *bool     { return &v.posSIBSegmentsIndef }
func BridgePosSIBsElemFieldReceived(v *PosSIBsElem) *bool                { return &v.received }
func BridgePosSIBsElemFieldReceivedBytes(v *PosSIBsElem) *aper.WireSpan  { return &v.receivedBytes }
func BridgePosSIBsElemFieldReplay(v *PosSIBsElem) *aper.Snapshot         { return &v.replay }
func BridgePosSIBsElemFieldStream(v *PosSIBsElem) *aper.WireSpan         { return &v.stream }
func BridgePosSIBsElemFieldWithoutReplay(v *PosSIBsElem) *bool           { return &v.withoutReplay }
func BridgePosSIBsElemMethodMarshalAPERBudget(v *PosSIBsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERChanged(v *PosSIBsElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBsElemMethodMarshalAPERChangedValue(v *PosSIBsElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBsElemMethodMarshalAPERFreshValue(v *PosSIBsElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERLegacy(v *PosSIBsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBsElemMethodMarshalAPERPlanned(v *PosSIBsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERTo(v *PosSIBsElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsElemMethodUnmarshalAPERFrom(v *PosSIBsElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsElemMethodUnmarshalAPERLegacy(v *PosSIBsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBsElemMethodUnmarshalAPERWithOptions(v *PosSIBsElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBsElemValueCodecFieldCapture(v *PosSIBsElemValueCodec) *func(PosSIBsElem, aper.DecodeState) (PosSIBsElem, aper.Snapshot) {
	return &v.capture
}
func BridgePosSIBsElemValueCodecFieldCompare(v *PosSIBsElemValueCodec) *func(PosSIBsElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePosSIBsElemValueCodecFieldContext(v *PosSIBsElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsElemValueCodecFieldDecode(v *PosSIBsElemValueCodec) *func([]byte, aper.DecodeState) (PosSIBsElem, error) {
	return &v.decode
}
func BridgePosSIBsElemValueCodecFieldEncode(v *PosSIBsElemValueCodec) *func(PosSIBsElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBsElemValueCodecFieldPath(v *PosSIBsElemValueCodec) *aper.Path { return &v.path }
func BridgePosSIBsElemValueCodecMethodEncodeBudget(v PosSIBsElemValueCodec, a0 PosSIBsElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBsElemValueCodecMethodEncodeChanged(v PosSIBsElemValueCodec, a0 PosSIBsElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBsValueCodecFieldCapture(v *PosSIBsValueCodec) *func(PosSIBs, aper.DecodeState) (PosSIBs, aper.Snapshot) {
	return &v.capture
}
func BridgePosSIBsValueCodecFieldCompare(v *PosSIBsValueCodec) *func(PosSIBs, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePosSIBsValueCodecFieldContext(v *PosSIBsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsValueCodecFieldDecode(v *PosSIBsValueCodec) *func([]byte, aper.DecodeState) (PosSIBs, error) {
	return &v.decode
}
func BridgePosSIBsValueCodecFieldEncode(v *PosSIBsValueCodec) *func(PosSIBs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBsValueCodecFieldPath(v *PosSIBsValueCodec) *aper.Path { return &v.path }
func BridgePosSIBsValueCodecMethodEncodeBudget(v PosSIBsValueCodec, a0 PosSIBs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBsValueCodecMethodEncodeChanged(v PosSIBsValueCodec, a0 PosSIBs, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULConfigurationAPERValueFieldContext(v *ULConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULConfigurationAPERValueFieldReceived(v *ULConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeULConfigurationAPERValueFieldReplay(v *ULConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeULConfigurationAPERValueFieldWithoutReplay(v *ULConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeULConfigurationFieldExtCount(v *ULConfiguration) *int64   { return &v.extCount }
func BridgeULConfigurationFieldExtData(v *ULConfiguration) *[][]byte { return &v.extData }
func BridgeULConfigurationFieldExtOrigin(v *ULConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeULConfigurationFieldExtPresent(v *ULConfiguration) *[]bool       { return &v.extPresent }
func BridgeULConfigurationFieldExtWire(v *ULConfiguration) *[]aper.WireSpan { return &v.extWire }
func BridgeULConfigurationFieldPerExtPadding(v *ULConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeULConfigurationFieldPerPadding(v *ULConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeULConfigurationFieldReceived(v *ULConfiguration) *bool { return &v.received }
func BridgeULConfigurationFieldReceivedBytes(v *ULConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeULConfigurationFieldReplay(v *ULConfiguration) *aper.Snapshot { return &v.replay }
func BridgeULConfigurationFieldSrsConfigurationIndef(v *ULConfiguration) *bool {
	return &v.srsConfigurationIndef
}
func BridgeULConfigurationFieldStream(v *ULConfiguration) *aper.WireSpan { return &v.stream }
func BridgeULConfigurationFieldWithoutReplay(v *ULConfiguration) *bool   { return &v.withoutReplay }
func BridgeULConfigurationMethodMarshalAPERBudget(v *ULConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERChanged(v *ULConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeULConfigurationMethodMarshalAPERChangedValue(v *ULConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeULConfigurationMethodMarshalAPERFreshValue(v *ULConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERLegacy(v *ULConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeULConfigurationMethodMarshalAPERPlanned(v *ULConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERTo(v *ULConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeULConfigurationMethodUnmarshalAPERFrom(v *ULConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeULConfigurationMethodUnmarshalAPERLegacy(v *ULConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeULConfigurationMethodUnmarshalAPERWithOptions(v *ULConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeULConfigurationValueCodecFieldCapture(v *ULConfigurationValueCodec) *func(ULConfiguration, aper.DecodeState) (ULConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeULConfigurationValueCodecFieldCompare(v *ULConfigurationValueCodec) *func(ULConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeULConfigurationValueCodecFieldContext(v *ULConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULConfigurationValueCodecFieldDecode(v *ULConfigurationValueCodec) *func([]byte, aper.DecodeState) (ULConfiguration, error) {
	return &v.decode
}
func BridgeULConfigurationValueCodecFieldEncode(v *ULConfigurationValueCodec) *func(ULConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULConfigurationValueCodecFieldPath(v *ULConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeULConfigurationValueCodecMethodEncodeBudget(v ULConfigurationValueCodec, a0 ULConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeULConfigurationValueCodecMethodEncodeChanged(v ULConfigurationValueCodec, a0 ULConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldCodec(v *UTDOAInformationFailureCauseIEBinding) *s05.CauseValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldGet(v *UTDOAInformationFailureCauseIEBinding) *func(*UTDOAInformationFailureIEValue) (*s05.Cause, bool) {
	return &v.get
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldInfo(v *UTDOAInformationFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldInject(v *UTDOAInformationFailureCauseIEBinding) *func(s05.Cause) UTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldGet(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(*UTDOAInformationFailureIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInject(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) UTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureIEFieldFieldReceived(v *UTDOAInformationFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationFailureIEFieldFieldReplay(v *UTDOAInformationFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureIEFieldFieldStream(v *UTDOAInformationFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v *UTDOAInformationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureIEFieldMethodMarshalAPERTo(v *UTDOAInformationFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationFailureIETableMethodInfoCause(v UTDOAInformationFailureIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUTDOAInformationFailureIETableMethodInfoCriticalityDiagnostics(v UTDOAInformationFailureIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUTDOAInformationFailureIEValueFieldId(v *UTDOAInformationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationFailureIEValueFieldIsOpaque(v *UTDOAInformationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationFailureIEValueFieldOpaque(v *UTDOAInformationFailureIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationFailureIEValueFieldReceived(v *UTDOAInformationFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationFailureIEValueFieldReplay(v *UTDOAInformationFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureIEValueFieldRowCause(v *UTDOAInformationFailureIEValue) **s05.Cause {
	return &v.rowCause
}
func BridgeUTDOAInformationFailureIEValueFieldRowCriticalityDiagnostics(v *UTDOAInformationFailureIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUTDOAInformationFailureIEValueFieldWithoutReplay(v *UTDOAInformationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureFraming(v UTDOAInformationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureSemantics(v UTDOAInformationFailureIEValue, a0 aper.SemanticCapture) UTDOAInformationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureSnapshot(v UTDOAInformationFailureIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationFailureIEValueMethodCompareSemantics(v UTDOAInformationFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodDecode(v UTDOAInformationFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UTDOAInformationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodEncode(v UTDOAInformationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationFailureIEValueMethodEncodeFresh(v UTDOAInformationFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodMatchesID(v UTDOAInformationFailureIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodReason(v UTDOAInformationFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodRule(v UTDOAInformationFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldGet(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(*UTDOAInformationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInject(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) UTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeUTDOAInformationResponseIEFieldFieldReceived(v *UTDOAInformationResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationResponseIEFieldFieldReplay(v *UTDOAInformationResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseIEFieldFieldStream(v *UTDOAInformationResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v *UTDOAInformationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseIEFieldMethodMarshalAPERTo(v *UTDOAInformationResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationResponseIETableMethodInfoCriticalityDiagnostics(v UTDOAInformationResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUTDOAInformationResponseIETableMethodInfoULConfiguration(v UTDOAInformationResponseIETable) s00.FieldInfo {
	return v.infoULConfiguration()
}
func BridgeUTDOAInformationResponseIEValueFieldId(v *UTDOAInformationResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationResponseIEValueFieldIsOpaque(v *UTDOAInformationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationResponseIEValueFieldOpaque(v *UTDOAInformationResponseIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationResponseIEValueFieldReceived(v *UTDOAInformationResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationResponseIEValueFieldReplay(v *UTDOAInformationResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseIEValueFieldRowCriticalityDiagnostics(v *UTDOAInformationResponseIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUTDOAInformationResponseIEValueFieldRowULConfiguration(v *UTDOAInformationResponseIEValue) **ULConfiguration {
	return &v.rowULConfiguration
}
func BridgeUTDOAInformationResponseIEValueFieldWithoutReplay(v *UTDOAInformationResponseIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseIEValueMethodCaptureFraming(v UTDOAInformationResponseIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationResponseIEValueMethodCaptureSemantics(v UTDOAInformationResponseIEValue, a0 aper.SemanticCapture) UTDOAInformationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodCaptureSnapshot(v UTDOAInformationResponseIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationResponseIEValueMethodCompareSemantics(v UTDOAInformationResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodDecode(v UTDOAInformationResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UTDOAInformationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodEncode(v UTDOAInformationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationResponseIEValueMethodEncodeFresh(v UTDOAInformationResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodMatchesID(v UTDOAInformationResponseIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodReason(v UTDOAInformationResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodRule(v UTDOAInformationResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldCodec(v *UTDOAInformationResponseULConfigurationIEBinding) *ULConfigurationValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldGet(v *UTDOAInformationResponseULConfigurationIEBinding) *func(*UTDOAInformationResponseIEValue) (*ULConfiguration, bool) {
	return &v.get
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldInfo(v *UTDOAInformationResponseULConfigurationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldInject(v *UTDOAInformationResponseULConfigurationIEBinding) *func(ULConfiguration) UTDOAInformationResponseIEValue {
	return &v.inject
}
