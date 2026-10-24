// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s10 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s10

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q11 "math/big"
)

// ErrorIndicationIEContainer is the concrete ProtocolIEContainer[ErrorIndicationIEValue].
type ErrorIndicationIEContainer []ErrorIndicationIEField

// ErrorIndicationIEField is the concrete ProtocolIEField[ErrorIndicationIEValue].
type ErrorIndicationIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         ErrorIndicationIEValue

	received q4.CompletePadding
}

func (v ErrorIndicationIEField) WithoutReplay() ErrorIndicationIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ErrorIndicationIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ErrorIndicationIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ErrorIndicationIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndicationIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero ErrorIndicationIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEContainer []OTDOAInformationFailureIEField

// OTDOAInformationFailureIEField is the concrete ProtocolIEField[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         OTDOAInformationFailureIEValue

	received q4.CompletePadding
}

func (v OTDOAInformationFailureIEField) WithoutReplay() OTDOAInformationFailureIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOAInformationFailureIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationFailureIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationFailureIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationFailureIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero OTDOAInformationFailureIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// UTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEContainer []UTDOAInformationResponseIEField

// UTDOAInformationResponseIEField is the concrete ProtocolIEField[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         UTDOAInformationResponseIEValue

	received q4.CompletePadding
}

func (v UTDOAInformationResponseIEField) WithoutReplay() UTDOAInformationResponseIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *UTDOAInformationResponseIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationResponseIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationResponseIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationResponseIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero UTDOAInformationResponseIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// UTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEContainer []UTDOAInformationFailureIEField

// UTDOAInformationFailureIEField is the concrete ProtocolIEField[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         UTDOAInformationFailureIEValue

	received q4.CompletePadding
}

func (v UTDOAInformationFailureIEField) WithoutReplay() UTDOAInformationFailureIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *UTDOAInformationFailureIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationFailureIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationFailureIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationFailureIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero UTDOAInformationFailureIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ECIDMeasurementInitiationFailureMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureMeasurementIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.MeasurementIDValueCodec
	inject func(q5.MeasurementID,

	) q9.ECIDMeasurementInitiationFailureIEValue

	get func(*q9.ECIDMeasurementInitiationFailureIEValue,

	) (*q5.MeasurementID,

		bool)
}

func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Codec() q5.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) New(value q5.MeasurementID,

) (q9.ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return q9.ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationFailureMeasurementIDIEBinding) Get(field *q9.ECIDMeasurementInitiationFailureIEField) (*q5.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCauseIEBinding is the concrete IEBinding[Cause, ErrorIndicationIEValue].
type ErrorIndicationCauseIEBinding struct {
	info   q5.FieldInfo
	codec  q10.CauseValueCodec
	inject func(q10.Cause,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*q10.Cause,

		bool)
}

func (b ErrorIndicationCauseIEBinding) Info() q5.FieldInfo         { return b.info }
func (b ErrorIndicationCauseIEBinding) Codec() q10.CauseValueCodec { return b.codec }
func (b ErrorIndicationCauseIEBinding) New(value q10.Cause,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ErrorIndicationCauseIEBinding) Get(field *ErrorIndicationIEField) (*q10.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ErrorIndicationIEValue].
type ErrorIndicationCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q9.CriticalityDiagnosticsValueCodec
	inject func(q9.CriticalityDiagnostics,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*q9.CriticalityDiagnostics,

		bool)
}

func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo { return b.info }
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Codec() q9.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) New(value q9.CriticalityDiagnostics,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Get(field *ErrorIndicationIEField) (*q9.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCauseIEBinding struct {
	info   q5.FieldInfo
	codec  q10.CauseValueCodec
	inject func(q10.Cause,

	) OTDOAInformationFailureIEValue

	get func(*OTDOAInformationFailureIEValue,

	) (*q10.Cause,

		bool)
}

func (b OTDOAInformationFailureCauseIEBinding) Info() q5.FieldInfo         { return b.info }
func (b OTDOAInformationFailureCauseIEBinding) Codec() q10.CauseValueCodec { return b.codec }
func (b OTDOAInformationFailureCauseIEBinding) New(value q10.Cause,

) (OTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationFailureCauseIEBinding) Get(field *OTDOAInformationFailureIEField) (*q10.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q9.CriticalityDiagnosticsValueCodec
	inject func(q9.CriticalityDiagnostics,

	) OTDOAInformationFailureIEValue

	get func(*OTDOAInformationFailureIEValue,

	) (*q9.CriticalityDiagnostics,

		bool)
}

func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo { return b.info }
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Codec() q9.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) New(value q9.CriticalityDiagnostics,

) (OTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationFailureCriticalityDiagnosticsIEBinding) Get(field *OTDOAInformationFailureIEField) (*q9.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCauseIEBinding struct {
	info   q5.FieldInfo
	codec  q10.CauseValueCodec
	inject func(q10.Cause,

	) UTDOAInformationFailureIEValue

	get func(*UTDOAInformationFailureIEValue,

	) (*q10.Cause,

		bool)
}

func (b UTDOAInformationFailureCauseIEBinding) Info() q5.FieldInfo         { return b.info }
func (b UTDOAInformationFailureCauseIEBinding) Codec() q10.CauseValueCodec { return b.codec }
func (b UTDOAInformationFailureCauseIEBinding) New(value q10.Cause,

) (UTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationFailureCauseIEBinding) Get(field *UTDOAInformationFailureIEField) (*q10.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q9.CriticalityDiagnosticsValueCodec
	inject func(q9.CriticalityDiagnostics,

	) UTDOAInformationFailureIEValue

	get func(*UTDOAInformationFailureIEValue,

	) (*q9.CriticalityDiagnostics,

		bool)
}

func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo { return b.info }
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Codec() q9.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) New(value q9.CriticalityDiagnostics,

) (UTDOAInformationFailureIEField, error) {
	if b.inject == nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationFailureCriticalityDiagnosticsIEBinding) Get(field *UTDOAInformationFailureIEField) (*q9.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationResponseULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseULConfigurationIEBinding struct {
	info   q5.FieldInfo
	codec  ULConfigurationValueCodec
	inject func(ULConfiguration,

	) UTDOAInformationResponseIEValue

	get func(*UTDOAInformationResponseIEValue,

	) (*ULConfiguration,

		bool)
}

func (b UTDOAInformationResponseULConfigurationIEBinding) Info() q5.FieldInfo { return b.info }
func (b UTDOAInformationResponseULConfigurationIEBinding) Codec() ULConfigurationValueCodec {
	return b.codec
}
func (b UTDOAInformationResponseULConfigurationIEBinding) New(value ULConfiguration,

) (UTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationResponseULConfigurationIEBinding) Get(field *UTDOAInformationResponseIEField) (*ULConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ULConfigurationValueCodec is the concrete ValueCodec[ULConfiguration].
type ULConfigurationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ULConfiguration, q4.DecodeState,

	) (ULConfiguration, q4.Snapshot,

	)
	compare func(ULConfiguration, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ULConfiguration,

		error)
	encode func(ULConfiguration,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ULConfigurationValueCodec) New(value ULConfiguration,

) (ULConfigurationAPERValue, error) {
	if c.encode == nil {
		return ULConfigurationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ULConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ULConfigurationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ULConfigurationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ULConfigurationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ULConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ULConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ULConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ULConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ULConfigurationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ULConfigurationValueCodec) EncodeAPER(value ULConfigurationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c ULConfigurationValueCodec) encodeBudget(value ULConfiguration,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ULConfigurationValueCodec) encodeChanged(value ULConfiguration,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// UTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q9.CriticalityDiagnosticsValueCodec
	inject func(q9.CriticalityDiagnostics,

	) UTDOAInformationResponseIEValue

	get func(*UTDOAInformationResponseIEValue,

	) (*q9.CriticalityDiagnostics,

		bool)
}

func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo { return b.info }
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Codec() q9.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) New(value q9.CriticalityDiagnostics,

) (UTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationResponseCriticalityDiagnosticsIEBinding) Get(field *UTDOAInformationResponseIEField) (*q9.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PosSIBsValueCodec is the concrete ValueCodec[PosSIBs].
type PosSIBsValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PosSIBs, q4.DecodeState,

	) (PosSIBs, q4.Snapshot,

	)
	compare func(PosSIBs, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PosSIBs,

		error)
	encode func(PosSIBs,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PosSIBsValueCodec) New(value PosSIBs,

) (PosSIBsAPERValue, error) {
	if c.encode == nil {
		return PosSIBsAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PosSIBsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PosSIBsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PosSIBsValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PosSIBsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PosSIBsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PosSIBsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PosSIBsValueCodec) EncodeAPER(value PosSIBsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c PosSIBsValueCodec) encodeBudget(value PosSIBs,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBsValueCodec) encodeChanged(value PosSIBs,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PosSIBsElemValueCodec is the concrete ValueCodec[PosSIBsElem].
type PosSIBsElemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PosSIBsElem, q4.DecodeState,

	) (PosSIBsElem, q4.Snapshot,

	)
	compare func(PosSIBsElem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PosSIBsElem,

		error)
	encode func(PosSIBsElem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PosSIBsElemValueCodec) New(value PosSIBsElem,

) (PosSIBsElemAPERValue, error) {
	if c.encode == nil {
		return PosSIBsElemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PosSIBsElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBsElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PosSIBsElemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PosSIBsElemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PosSIBsElemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBsElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PosSIBsElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBsElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBsElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PosSIBsElemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PosSIBsElemValueCodec) EncodeAPER(value PosSIBsElemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c PosSIBsElemValueCodec) encodeBudget(value PosSIBsElem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBsElemValueCodec) encodeChanged(value PosSIBsElem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ULConfigurationAPERValue is the concrete APERValue[ULConfiguration].
type ULConfigurationAPERValue struct {
	context q5.BridgeCodecContext
	Value   ULConfiguration

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ULConfigurationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ULConfigurationAPERValue) WithoutReplay() ULConfigurationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBsAPERValue is the concrete APERValue[PosSIBs].
type PosSIBsAPERValue struct {
	context q5.BridgeCodecContext
	Value   PosSIBs

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PosSIBsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PosSIBsAPERValue) WithoutReplay() PosSIBsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBsElemAPERValue is the concrete APERValue[PosSIBsElem].
type PosSIBsElemAPERValue struct {
	context q5.BridgeCodecContext
	Value   PosSIBsElem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PosSIBsElemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PosSIBsElemAPERValue) WithoutReplay() PosSIBsElemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

type PosSIBs = []PosSIBsElem

// ULConfiguration represents the ASN.1 type ULConfiguration (SEQUENCE).
type ULConfiguration struct {
	replay                q4.Snapshot
	stream                q4.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         q4.WireSpan
	Pci                   q5.PCI                         `asn1:"tag:0,context,implicit"`
	UlEarfcn              q5.EARFCN                      `asn1:"tag:1,context,implicit"`
	TimingAdvanceType1    *int64                         `asn1:"tag:2,context,implicit,optional" json:"TimingAdvanceType1,omitempty"`
	TimingAdvanceType2    *int64                         `asn1:"tag:3,context,implicit,optional" json:"TimingAdvanceType2,omitempty"`
	NumberOfTransmissions *q11.Int                       `asn1:"tag:4,context,implicit"`
	SrsConfiguration      q9.SRSConfigurationForAllCells `asn1:"tag:5,context,implicit"`
	srsConfigurationIndef bool                           `asn1:"-" json:"-"`
	extCount              int64                          `asn1:"-" json:"-"`
	extPresent            []bool                         `asn1:"-" json:"-"`
	extData               [][]byte                       `asn1:"-" json:"-"`
	perPadding            q4.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding         []q4.CompletePadding           `asn1:"-" json:"-"`
	extOrigin             []q4.OpaqueOrigin
	extWire               []q4.WireSpan
}

// PosSIBsElem represents the ASN.1 type PosSIBs-Elem (SEQUENCE).
type PosSIBsElem struct {
	replay                        q4.Snapshot
	stream                        q4.WireSpan
	withoutReplay                 bool
	received                      bool
	receivedBytes                 q4.WireSpan
	PosSIBType                    q5.PosSIBType                      `asn1:"tag:0,context,implicit"`
	PosSIBSegments                q12.PosSIBSegments                 `asn1:"tag:1,context,implicit"`
	posSIBSegmentsIndef           bool                               `asn1:"-" json:"-"`
	AssistanceInformationMetaData *q10.AssistanceInformationMetaData `asn1:"tag:2,context,implicit,optional" json:"AssistanceInformationMetaData,omitempty"`
	BroadcastPriority             *q11.Int                           `asn1:"tag:3,context,implicit,optional" json:"BroadcastPriority,omitempty"`
	IEExtensions                  q13.PosSIBsExtIEsExtContainer      `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                               `asn1:"-" json:"-"`
	extCount                      int64                              `asn1:"-" json:"-"`
	extPresent                    []bool                             `asn1:"-" json:"-"`
	extData                       [][]byte                           `asn1:"-" json:"-"`
	perPadding                    q4.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding                 []q4.CompletePadding               `asn1:"-" json:"-"`
	extOrigin                     []q4.OpaqueOrigin
	extWire                       []q4.WireSpan
}
type BridgeAsn1cAPERPosSIBsListValue struct{ Value PosSIBs }

// MarshalAPER encodes ULConfiguration to APER format.
func (v *ULConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ULConfiguration) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q4.EncodeBoolean(bb, v.TimingAdvanceType1 != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.TimingAdvanceType2 != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.Pci, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound17, true); err != nil {
		return q6.Errorf("encoding pci: %w", err)
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound20, true); err != nil {
		return q6.Errorf("encoding ul-earfcn: %w", err)
	}
	if v.TimingAdvanceType1 != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType1), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false); err != nil {
			return q6.Errorf("encoding timingAdvanceType1: %w", err)
		}
	}
	if v.TimingAdvanceType2 != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType2), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false); err != nil {
			return q6.Errorf("encoding timingAdvanceType2: %w", err)
		}
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound16, true); err != nil {
		return q6.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := q4.EncodeCollection(bb, int64(len(v.SrsConfiguration)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_srsconfiguration < 0 || fragmentOffset_srsconfiguration > int64(len(v.SrsConfiguration)) || fragmentLength_srsconfiguration < 0 || fragmentLength_srsconfiguration > int64(len(v.SrsConfiguration[fragmentOffset_srsconfiguration:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SrsConfiguration[fragmentOffset_srsconfiguration : fragmentOffset_srsconfiguration+fragmentLength_srsconfiguration] {
			if err := q9.BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding srsConfiguration element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding srsConfiguration: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ULConfiguration from APER format.
func (v *ULConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ULConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ULConfiguration) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ULConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ULConfiguration")
	}
	padding, err := q4.CaptureFinalBits(bb, "ULConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "ULConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ULConfiguration) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ULConfiguration{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_timingadvancetype1, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_timingadvancetype2, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return q7.WrapDecodePath(err, "Pci")
	}
	v.Pci = val_pci
	val_ulearfcn, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return q7.WrapDecodePath(err, "UlEarfcn")
	}
	v.UlEarfcn = val_ulearfcn
	if opt_timingadvancetype1 {
		val_timingadvancetype1, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false)
		if err != nil {
			return q7.WrapDecodePath(err, "TimingAdvanceType1")
		}
		if err := q4.ChargeValue(bb, val_timingadvancetype1); err != nil {
			return err
		}
		v.TimingAdvanceType1 = (*int64)(bb.OwnInt64(int64(val_timingadvancetype1)))
	}
	if opt_timingadvancetype2 {
		val_timingadvancetype2, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false)
		if err != nil {
			return q7.WrapDecodePath(err, "TimingAdvanceType2")
		}
		if err := q4.ChargeValue(bb, val_timingadvancetype2); err != nil {
			return err
		}
		v.TimingAdvanceType2 = (*int64)(bb.OwnInt64(int64(val_timingadvancetype2)))
	}
	val_numberoftransmissions, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound16, true)
	if err != nil {
		return q7.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	toleranceMark_srsconfiguration := bb.EnterComponent("SrsConfiguration")
	v.SrsConfiguration = make(q9.SRSConfigurationForAllCells, 0)
	_, errCollection_srsconfiguration := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_srsconfiguration < 0 || fragmentLength_srsconfiguration < 0 || fragmentLength_srsconfiguration > int64(^uint(0)>>1) || fragmentOffset_srsconfiguration > int64(^uint(0)>>1)-fragmentLength_srsconfiguration {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_srsconfiguration; i++ {
			var elem q9.SRSConfigurationForOneCell
			elementMark := bb.EnterIndex(fragmentOffset_srsconfiguration + i)
			if err := q9.BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("SrsConfiguration[%d]", fragmentOffset_srsconfiguration+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.SrsConfiguration, elem); err != nil {
				return err
			} else {
				v.SrsConfiguration = next
			}
		}
		return nil
	})
	if errCollection_srsconfiguration != nil {
		return q7.WrapDecodePath(errCollection_srsconfiguration, "SrsConfiguration")
	}
	bb.LeaveComponent(toleranceMark_srsconfiguration)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PosSIBsElem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q4.EncodeBoolean(bb, v.AssistanceInformationMetaData != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.BroadcastPriority != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return q6.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := q4.EncodeCollection(bb, int64(len(v.PosSIBSegments)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_possibsegments < 0 || fragmentOffset_possibsegments > int64(len(v.PosSIBSegments)) || fragmentLength_possibsegments < 0 || fragmentLength_possibsegments > int64(len(v.PosSIBSegments[fragmentOffset_possibsegments:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PosSIBSegments[fragmentOffset_possibsegments : fragmentOffset_possibsegments+fragmentLength_possibsegments] {
			if err := q12.BridgePosSIBSegmentsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding posSIB-Segments element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding posSIB-Segments: %w", err)
	}
	if v.AssistanceInformationMetaData != nil {
		if err := q10.BridgeAssistanceInformationMetaDataMethodMarshalAPERTo(v.AssistanceInformationMetaData, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding assistanceInformationMetaData: %w", err)
		}
	}
	if v.BroadcastPriority != nil {
		if err := q4.EncodeIntegerBigBoundsAligned(bb, v.BroadcastPriority, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound8, true); err != nil {
			return q6.Errorf("encoding broadcastPriority: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q13.BridgePosSIBsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes PosSIBsElem from APER format.
func (v *PosSIBsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBsElem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PosSIBsElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "PosSIBsElem")
	}
	padding, err := q4.CaptureFinalBits(bb, "PosSIBsElem")
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PosSIBsElem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBsElem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_assistanceinformationmetadata, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_broadcastpriority, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_possibtype, err := q4.DecodeEnumeratedAligned(bb, 27, true, q4.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = q5.PosSIBType(val_possibtype)
	toleranceMark_possibsegments := bb.EnterComponent("PosSIBSegments")
	v.PosSIBSegments = make(q12.PosSIBSegments, 0)
	_, errCollection_possibsegments := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_possibsegments < 0 || fragmentLength_possibsegments < 0 || fragmentLength_possibsegments > int64(^uint(0)>>1) || fragmentOffset_possibsegments > int64(^uint(0)>>1)-fragmentLength_possibsegments {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_possibsegments; i++ {
			var elem q12.PosSIBSegmentsElem
			elementMark := bb.EnterIndex(fragmentOffset_possibsegments + i)
			if err := q12.BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("PosSIBSegments[%d]", fragmentOffset_possibsegments+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.PosSIBSegments, elem); err != nil {
				return err
			} else {
				v.PosSIBSegments = next
			}
		}
		return nil
	})
	if errCollection_possibsegments != nil {
		return q7.WrapDecodePath(errCollection_possibsegments, "PosSIBSegments")
	}
	bb.LeaveComponent(toleranceMark_possibsegments)
	if opt_assistanceinformationmetadata {
		toleranceMark_assistanceinformationmetadata := bb.EnterComponent("AssistanceInformationMetaData")
		var dec_assistanceinformationmetadata q10.AssistanceInformationMetaData
		if err := q10.BridgeAssistanceInformationMetaDataMethodUnmarshalAPERFrom(&dec_assistanceinformationmetadata, bb); err != nil {
			return q7.WrapDecodePath(err, "AssistanceInformationMetaData")
		}
		if err := q4.ChargeValue(bb, dec_assistanceinformationmetadata); err != nil {
			return err
		}
		v.AssistanceInformationMetaData = &dec_assistanceinformationmetadata
		bb.LeaveComponent(toleranceMark_assistanceinformationmetadata)
	}
	if opt_broadcastpriority {
		val_broadcastpriority, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound8, true)
		if err != nil {
			return q7.WrapDecodePath(err, "BroadcastPriority")
		}
		v.BroadcastPriority = val_broadcastpriority
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q13.PosSIBsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q13.PosSIBsExtIEsExtField
				if err := q13.BridgePosSIBsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q4.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q7.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
func (v *PosSIBsElem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBsElem) WithoutReplay() PosSIBsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PosSIBsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULConfiguration) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "ULConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULConfiguration) WithoutReplay() ULConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ULConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PosSIBsElem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PosSIBsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PosSIBsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PosSIBsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ULConfiguration) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ULConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ULConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ULConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *PosSIBsElem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PosSIBsElem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PosSIBsElem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PosSIBsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PosSIBsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PosSIBsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PosSIBsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PosSIBsElem")
}
func (v *PosSIBsElem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBsElem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBsElem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *PosSIBsElem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBsElem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *ULConfiguration) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ULConfiguration")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ULConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaULConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ULConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ULConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ULConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ULConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ULConfiguration")
}
func (v *ULConfiguration) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ULConfiguration) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ULConfiguration) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ULConfiguration) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ULConfiguration) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *PosSIBsElem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PosSIBsElem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBsElem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBsElem{}
		return report, q4.OperationError(err, "PosSIBsElem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PosSIBsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ULConfiguration) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ULConfiguration")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ULConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaULConfiguration(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ULConfiguration{}
		return report, q4.OperationError(err, "ULConfiguration")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ULConfiguration")
}
func BridgeCaptureLPPaErrorIndicationIEValue(v *ErrorIndicationIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ErrorIndicationIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ErrorIndicationIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ErrorIndicationIEValue) captureSemantics(s q4.SemanticCapture) ErrorIndicationIEValue {
	BridgeCaptureLPPaErrorIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaErrorIndicationIEValue(v *ErrorIndicationIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ErrorIndicationIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaErrorIndicationIEValue(&v, &s)
	return s
}
func (v ErrorIndicationIEValue) WithoutReplay() ErrorIndicationIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaMBSFNsubframeConfiguration(v *q9.MBSFNsubframeConfiguration, s *q4.SemanticComparison) {
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
			q9.BridgeCompareLPPaMBSFNsubframeConfigurationValue(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOAInformationFailureIEValue(v *OTDOAInformationFailureIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationFailureIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v OTDOAInformationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationFailureIEValue) captureSemantics(s q4.SemanticCapture) OTDOAInformationFailureIEValue {
	BridgeCaptureLPPaOTDOAInformationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationFailureIEValue(v *OTDOAInformationFailureIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationFailureIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationFailureIEValue(&v, &s)
	return s
}
func (v OTDOAInformationFailureIEValue) WithoutReplay() OTDOAInformationFailureIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCompareLPPaPosSIBSegments(v *q12.PosSIBSegments, s *q4.SemanticComparison) {
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
			q12.BridgeCompareLPPaPosSIBSegmentsElem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaPosSIBs(v *PosSIBs, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaPosSIBs(v *PosSIBs, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaPosSIBsElem(v *PosSIBsElem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaPosSIBType(&v.PosSIBType, s)
	q9.BridgeCaptureLPPaPosSIBSegments(&v.PosSIBSegments, s)
	{
		f := s.Begin()
		s.Bool(v.AssistanceInformationMetaData == nil)
		if v.AssistanceInformationMetaData != nil {
			q10.BridgeCaptureLPPaAssistanceInformationMetaData(v.AssistanceInformationMetaData, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.BroadcastPriority)
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	q10.BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBsElem(v *PosSIBsElem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaPosSIBType(&v.PosSIBType, s)
	BridgeCompareLPPaPosSIBSegments(&v.PosSIBSegments, s)
	{
		f := s.Begin()
		s.Bool(v.AssistanceInformationMetaData == nil)
		if v.AssistanceInformationMetaData != nil {
			q10.BridgeCompareLPPaAssistanceInformationMetaData(v.AssistanceInformationMetaData, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.BroadcastPriority)
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	q10.BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForAllCells(v *q9.SRSConfigurationForAllCells, s *q4.SemanticComparison) {
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
			q9.BridgeCompareLPPaSRSConfigurationForOneCell(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaULConfiguration(v *ULConfiguration, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaPCI(&v.Pci, s)
	q5.BridgeCaptureLPPaEARFCN(&v.UlEarfcn, s)
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
	q9.BridgeCaptureLPPaSRSConfigurationForAllCells(&v.SrsConfiguration, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaULConfiguration(v *ULConfiguration, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaPCI(&v.Pci, s)
	q14.BridgeCompareLPPaEARFCN(&v.UlEarfcn, s)
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType1 == nil)
		if v.TimingAdvanceType1 != nil {
			s.Int(int64((*v.TimingAdvanceType1)))
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TimingAdvanceType2 == nil)
		if v.TimingAdvanceType2 != nil {
			s.Int(int64((*v.TimingAdvanceType2)))
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, q4.Snapshot{}, false)
	}
	BridgeCompareLPPaSRSConfigurationForAllCells(&v.SrsConfiguration, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationFailureIEValue(v *UTDOAInformationFailureIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationFailureIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v UTDOAInformationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationFailureIEValue) captureSemantics(s q4.SemanticCapture) UTDOAInformationFailureIEValue {
	BridgeCaptureLPPaUTDOAInformationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationFailureIEValue(v *UTDOAInformationFailureIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q10.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationFailureIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationFailureIEValue(&v, &s)
	return s
}
func (v UTDOAInformationFailureIEValue) WithoutReplay() UTDOAInformationFailureIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaUTDOAInformationResponseIEValue(v *UTDOAInformationResponseIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					BridgeCaptureLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationResponseIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v UTDOAInformationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationResponseIEValue) captureSemantics(s q4.SemanticCapture) UTDOAInformationResponseIEValue {
	BridgeCaptureLPPaUTDOAInformationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationResponseIEValue(v *UTDOAInformationResponseIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					BridgeCompareLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q9.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationResponseIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationResponseIEValue(&v, &s)
	return s
}
func (v UTDOAInformationResponseIEValue) WithoutReplay() UTDOAInformationResponseIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}

type ErrorIndicationIEValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *q10.Cause
	rowCriticalityDiagnostics *q9.CriticalityDiagnostics
}

func (v ErrorIndicationIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(0):
		return v.rowCause != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *ErrorIndicationIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ErrorIndicationIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs"}}
}
func (ErrorIndicationIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *ErrorIndicationIEValue) AsCause() (*q10.Cause, bool) {
	if v == nil || v.id != q5.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *ErrorIndicationIEValue) AsCriticalityDiagnostics() (*q9.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ErrorIndicationIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	out := ErrorIndicationIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value q10.Cause
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "Cause:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*q10.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*q10.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeCauseFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q9.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q9.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q9.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ErrorIndicationIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, q6.Errorf("%s missing value", "ErrorIndication-IEs.id-Cause:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "ErrorIndication-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "ErrorIndicationIEValue:", v.id)
	}
}

type OTDOAInformationFailureIEValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *q10.Cause
	rowCriticalityDiagnostics *q9.CriticalityDiagnostics
}

func (v OTDOAInformationFailureIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(0):
		return v.rowCause != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *OTDOAInformationFailureIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationFailureIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs"}}
}
func (OTDOAInformationFailureIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *OTDOAInformationFailureIEValue) AsCause() (*q10.Cause, bool) {
	if v == nil || v.id != q5.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *OTDOAInformationFailureIEValue) AsCriticalityDiagnostics() (*q9.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v OTDOAInformationFailureIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (OTDOAInformationFailureIEValue, error) {
	out := OTDOAInformationFailureIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value q10.Cause
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "Cause:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*q10.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*q10.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeCauseFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q9.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q9.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q9.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationFailureIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationFailure-IEs.id-Cause:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "OTDOAInformationFailureIEValue:", v.id)
	}
}

type UTDOAInformationFailureIEValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowCause                  *q10.Cause
	rowCriticalityDiagnostics *q9.CriticalityDiagnostics
}

func (v UTDOAInformationFailureIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(0):
		return v.rowCause != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *UTDOAInformationFailureIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationFailureIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs"}}
}
func (UTDOAInformationFailureIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(0):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *UTDOAInformationFailureIEValue) AsCause() (*q10.Cause, bool) {
	if v == nil || v.id != q5.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *UTDOAInformationFailureIEValue) AsCriticalityDiagnostics() (*q9.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UTDOAInformationFailureIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (UTDOAInformationFailureIEValue, error) {
	out := UTDOAInformationFailureIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value q10.Cause
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "Cause:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*q10.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*q10.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeCauseFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q9.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q9.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q9.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationFailureIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, q6.Errorf("%s missing value", "UTDOAInformationFailure-IEs.id-Cause:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "UTDOAInformationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "UTDOAInformationFailureIEValue:", v.id)
	}
}

type UTDOAInformationResponseIEValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowULConfiguration        *ULConfiguration
	rowCriticalityDiagnostics *q9.CriticalityDiagnostics
}

func (v UTDOAInformationResponseIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(13):
		return v.rowULConfiguration != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *UTDOAInformationResponseIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationResponseIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs"}}
}
func (UTDOAInformationResponseIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(13):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *UTDOAInformationResponseIEValue) AsULConfiguration() (*ULConfiguration, bool) {
	if v == nil || v.id != q5.ProtocolIEID(13) || v.rowULConfiguration == nil {
		return nil, false
	}
	return v.rowULConfiguration, true
}
func (v *UTDOAInformationResponseIEValue) AsCriticalityDiagnostics() (*q9.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UTDOAInformationResponseIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (UTDOAInformationResponseIEValue, error) {
	out := UTDOAInformationResponseIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 13, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(13):
		replayUsage := scope.Usage()
		var value ULConfiguration
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "ULConfiguration:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "ULConfiguration")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowULConfiguration = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q9.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q9.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q9.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationResponseIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(13):
		if v.rowULConfiguration == nil {
			return nil, q6.Errorf("%s missing value", "UTDOAInformationResponse-IEs.id-ULConfiguration:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "UTDOAInformationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "UTDOAInformationResponseIEValue:", v.id)
	}
}

type ECIDMeasurementInitiationFailureIETable struct{}

func ECIDMeasurementInitiationFailureIEs() ECIDMeasurementInitiationFailureIETable {
	return ECIDMeasurementInitiationFailureIETable{}
}
func (ECIDMeasurementInitiationFailureIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationFailureIETable) infoESMLCUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: q5.ProtocolIEID(2), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementInitiationFailureIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationFailureMeasurementIDIEBinding {
	return ECIDMeasurementInitiationFailureMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero q9.ECIDMeasurementInitiationFailureIEValue
			decoded, err := q9.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, q5.ProtocolIEID(2), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return q9.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() q9.ECIDMeasurementInitiationFailureIEValue {
				sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(2)
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q14.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) q9.ECIDMeasurementInitiationFailureIEValue {
			return func() q9.ECIDMeasurementInitiationFailureIEValue {
				sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(2)
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q9.ECIDMeasurementInitiationFailureIEValue) (*q5.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationFailureIETable) infoCause() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: q5.ProtocolIEID(0), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-Cause"}}}
}
func (t ECIDMeasurementInitiationFailureIETable) Cause() q9.ECIDMeasurementInitiationFailureCauseIEBinding {
	return func() q9.ECIDMeasurementInitiationFailureCauseIEBinding {
		sealed := q9.ECIDMeasurementInitiationFailureCauseIEBinding{}
		*q9.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInfo(&sealed) = t.infoCause()
		*q9.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldCodec(&sealed) = func() q10.CauseValueCodec {
			sealed := q10.CauseValueCodec{}
			*q10.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
			*q10.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.Cause, error) {
				raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty q10.Cause
					return empty, err
				}
				var zero q9.ECIDMeasurementInitiationFailureIEValue
				decoded, err := q9.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, q5.ProtocolIEID(0), raw)
				if err != nil {
					var empty q10.Cause
					return empty, err
				}
				value, ok := decoded.AsCause()
				if !ok {
					var empty q10.Cause
					return empty, q6.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-Cause: no selected value")
				}
				return *value, nil
			}
			*q10.BridgeCauseValueCodecFieldEncode(&sealed) = func(value q10.Cause, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
				return q9.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() q9.ECIDMeasurementInitiationFailureIEValue {
					sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
					*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(0)
					*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*q10.BridgeCauseValueCodecFieldCapture(&sealed) = func(v q10.Cause, options q4.DecodeState) (q10.Cause, q4.Snapshot) {
				s := q4.SemanticCaptureFor(options)
				f := s.Begin()
				q10.BridgeCaptureLPPaCause(&v, &s)
				var root q4.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*q10.BridgeCauseValueCodecFieldCompare(&sealed) = func(v q10.Cause, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
				s := q4.NewSemanticComparison(root,
					limits)
				f := s.Begin()
				q10.BridgeCompareLPPaCause(&v, &s)
				s.End(
					f, root, false)
				return s.Plan()
			}
			*q10.BridgeCauseValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
				sealed := q5.BridgeCodecContext{}
				*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
				return sealed
			}()
			return sealed
		}()
		*q9.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInject(&sealed) = func(value q10.Cause) q9.ECIDMeasurementInitiationFailureIEValue {
			return func() q9.ECIDMeasurementInitiationFailureIEValue {
				sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(0)
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(&sealed) = &value
				return sealed
			}()
		}
		*q9.BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldGet(&sealed) = func(value *q9.ECIDMeasurementInitiationFailureIEValue) (*q10.Cause, bool) { return value.AsCause() }
		return sealed
	}()
}
func (ECIDMeasurementInitiationFailureIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationFailureIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t ECIDMeasurementInitiationFailureIETable) CriticalityDiagnostics() q9.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding {
	return func() q9.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding {
		sealed := q9.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding{}
		*q9.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*q9.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() q9.CriticalityDiagnosticsValueCodec {
			sealed := q9.CriticalityDiagnosticsValueCodec{}
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.CriticalityDiagnostics, error) {
				raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty q9.CriticalityDiagnostics
					return empty, err
				}
				var zero q9.ECIDMeasurementInitiationFailureIEValue
				decoded, err := q9.BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(zero, q5.ProtocolIEID(1), raw)
				if err != nil {
					var empty q9.CriticalityDiagnostics
					return empty, err
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty q9.CriticalityDiagnostics
					return empty, q6.Errorf("binding E-CIDMeasurementInitiationFailure-IEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q9.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
				return q9.BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh((func() q9.ECIDMeasurementInitiationFailureIEValue {
					sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
					*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(1)
					*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q9.CriticalityDiagnostics, options q4.DecodeState) (q9.CriticalityDiagnostics, q4.Snapshot,

			) {
				s := q4.SemanticCaptureFor(options)
				f := s.Begin()
				q9.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
				var root q4.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q9.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
				s := q4.NewSemanticComparison(root, limits)
				f := s.Begin()
				q9.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan()
			}
			*q9.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
				sealed := q5.BridgeCodecContext{}
				*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				return sealed
			}()
			return sealed
		}()
		*q9.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value q9.CriticalityDiagnostics) q9.ECIDMeasurementInitiationFailureIEValue {
			return func() q9.ECIDMeasurementInitiationFailureIEValue {
				sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = q5.ProtocolIEID(1)
				*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*q9.BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *q9.ECIDMeasurementInitiationFailureIEValue) (*q9.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (t ECIDMeasurementInitiationFailureIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (q9.ECIDMeasurementInitiationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(2):
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(0):
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return q9.ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		return q9.ECIDMeasurementInitiationFailureIEField{Id: id, Criticality: criticality, Value: func() q9.ECIDMeasurementInitiationFailureIEValue {
			sealed := q9.ECIDMeasurementInitiationFailureIEValue{}
			*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldId(&sealed) = id
			*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldOpaque(&sealed) = retained
			*q9.BridgeECIDMeasurementInitiationFailureIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q4.OperationError(nil, "Opaque")
	}
}

type ErrorIndicationIETable struct{}

func ErrorIndicationIEs() ErrorIndicationIETable { return ErrorIndicationIETable{} }
func (ErrorIndicationIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs"}
		return sealed
	}()
}
func (ErrorIndicationIETable) infoCause() q5.FieldInfo {
	return q5.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: q5.ProtocolIEID(0), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs", Row: "id-Cause"}}}
}
func (t ErrorIndicationIETable) Cause() ErrorIndicationCauseIEBinding {
	return ErrorIndicationCauseIEBinding{info: t.infoCause(), codec: func() q10.CauseValueCodec {
		sealed := q10.CauseValueCodec{}
		*q10.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*q10.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.Cause, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(0), raw)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty q10.Cause
				return empty, q6.Errorf("binding ErrorIndication-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeCauseValueCodecFieldEncode(&sealed) = func(value q10.Cause, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: q5.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeCauseValueCodecFieldCapture(&sealed) = func(v q10.Cause, options q4.DecodeState) (q10.Cause, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaCause(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeCauseValueCodecFieldCompare(&sealed) = func(v q10.Cause, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q10.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q10.BridgeCauseValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.Cause) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: q5.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *ErrorIndicationIEValue) (*q10.Cause, bool) { return value.AsCause() }}
}
func (ErrorIndicationIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "ErrorIndication-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t ErrorIndicationIETable) CriticalityDiagnostics() ErrorIndicationCriticalityDiagnosticsIEBinding {
	return ErrorIndicationCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q9.CriticalityDiagnosticsValueCodec {
		sealed := q9.CriticalityDiagnosticsValueCodec{}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q9.CriticalityDiagnostics
				return empty, q6.Errorf("binding ErrorIndication-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q9.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q9.CriticalityDiagnostics, options q4.DecodeState) (q9.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q9.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.CriticalityDiagnostics) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *ErrorIndicationIEValue) (*q9.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t ErrorIndicationIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ErrorIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(0):
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return ErrorIndicationIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ErrorIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ErrorIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ErrorIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		return ErrorIndicationIEField{Id: id, Criticality: criticality, Value: ErrorIndicationIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationFailureIETable struct{}

func OTDOAInformationFailureIEs() OTDOAInformationFailureIETable {
	return OTDOAInformationFailureIETable{}
}
func (OTDOAInformationFailureIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs"}
		return sealed
	}()
}
func (OTDOAInformationFailureIETable) infoCause() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationFailureIEs().ID(), ID: q5.ProtocolIEID(0), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs", Row: "id-Cause"}}}
}
func (t OTDOAInformationFailureIETable) Cause() OTDOAInformationFailureCauseIEBinding {
	return OTDOAInformationFailureCauseIEBinding{info: t.infoCause(), codec: func() q10.CauseValueCodec {
		sealed := q10.CauseValueCodec{}
		*q10.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*q10.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.Cause, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			var zero OTDOAInformationFailureIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(0), raw)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty q10.Cause
				return empty, q6.Errorf("binding OTDOAInformationFailure-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeCauseValueCodecFieldEncode(&sealed) = func(value q10.Cause, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationFailureIEValue{id: q5.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeCauseValueCodecFieldCapture(&sealed) = func(v q10.Cause, options q4.DecodeState) (q10.Cause, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaCause(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeCauseValueCodecFieldCompare(&sealed) = func(v q10.Cause, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q10.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q10.BridgeCauseValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.Cause) OTDOAInformationFailureIEValue {
			return OTDOAInformationFailureIEValue{id: q5.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *OTDOAInformationFailureIEValue) (*q10.Cause, bool) { return value.AsCause() }}
}
func (OTDOAInformationFailureIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationFailureIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t OTDOAInformationFailureIETable) CriticalityDiagnostics() OTDOAInformationFailureCriticalityDiagnosticsIEBinding {
	return OTDOAInformationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q9.CriticalityDiagnosticsValueCodec {
		sealed := q9.CriticalityDiagnosticsValueCodec{}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			var zero OTDOAInformationFailureIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q9.CriticalityDiagnostics
				return empty, q6.Errorf("binding OTDOAInformationFailure-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q9.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationFailureIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q9.CriticalityDiagnostics, options q4.DecodeState) (q9.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q9.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.CriticalityDiagnostics) OTDOAInformationFailureIEValue {
			return OTDOAInformationFailureIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *OTDOAInformationFailureIEValue) (*q9.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t OTDOAInformationFailureIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (OTDOAInformationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(0):
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return OTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		return OTDOAInformationFailureIEField{Id: id, Criticality: criticality, Value: OTDOAInformationFailureIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

type UTDOAInformationFailureIETable struct{}

func UTDOAInformationFailureIEs() UTDOAInformationFailureIETable {
	return UTDOAInformationFailureIETable{}
}
func (UTDOAInformationFailureIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs"}
		return sealed
	}()
}
func (UTDOAInformationFailureIETable) infoCause() q5.FieldInfo {
	return q5.FieldInfo{Table: UTDOAInformationFailureIEs().ID(), ID: q5.ProtocolIEID(0), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs", Row: "id-Cause"}}}
}
func (t UTDOAInformationFailureIETable) Cause() UTDOAInformationFailureCauseIEBinding {
	return UTDOAInformationFailureCauseIEBinding{info: t.infoCause(), codec: func() q10.CauseValueCodec {
		sealed := q10.CauseValueCodec{}
		*q10.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*q10.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.Cause, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			var zero UTDOAInformationFailureIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(0), raw)
			if err != nil {
				var empty q10.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty q10.Cause
				return empty, q6.Errorf("binding UTDOAInformationFailure-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeCauseValueCodecFieldEncode(&sealed) = func(value q10.Cause, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationFailureIEValue{id: q5.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeCauseValueCodecFieldCapture(&sealed) = func(v q10.Cause, options q4.DecodeState) (q10.Cause, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaCause(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeCauseValueCodecFieldCompare(&sealed) = func(v q10.Cause, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q10.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q10.BridgeCauseValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.Cause) UTDOAInformationFailureIEValue {
			return UTDOAInformationFailureIEValue{id: q5.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *UTDOAInformationFailureIEValue) (*q10.Cause, bool) { return value.AsCause() }}
}
func (UTDOAInformationFailureIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: UTDOAInformationFailureIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationFailure-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UTDOAInformationFailureIETable) CriticalityDiagnostics() UTDOAInformationFailureCriticalityDiagnosticsIEBinding {
	return UTDOAInformationFailureCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q9.CriticalityDiagnosticsValueCodec {
		sealed := q9.CriticalityDiagnosticsValueCodec{}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			var zero UTDOAInformationFailureIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q9.CriticalityDiagnostics
				return empty, q6.Errorf("binding UTDOAInformationFailure-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q9.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationFailureIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q9.CriticalityDiagnostics, options q4.DecodeState) (q9.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q9.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.CriticalityDiagnostics) UTDOAInformationFailureIEValue {
			return UTDOAInformationFailureIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *UTDOAInformationFailureIEValue) (*q9.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UTDOAInformationFailureIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (UTDOAInformationFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(0):
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return UTDOAInformationFailureIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationFailureIEField{}, q4.OperationError(err, "Opaque")
		}
		return UTDOAInformationFailureIEField{Id: id, Criticality: criticality, Value: UTDOAInformationFailureIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

type UTDOAInformationResponseIETable struct{}

func UTDOAInformationResponseIEs() UTDOAInformationResponseIETable {
	return UTDOAInformationResponseIETable{}
}
func (UTDOAInformationResponseIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs"}
		return sealed
	}()
}
func (UTDOAInformationResponseIETable) infoULConfiguration() q5.FieldInfo {
	return q5.FieldInfo{Table: UTDOAInformationResponseIEs().ID(), ID: q5.ProtocolIEID(13), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ULConfiguration"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs", Row: "id-ULConfiguration"}}}
}
func (t UTDOAInformationResponseIETable) ULConfiguration() UTDOAInformationResponseULConfigurationIEBinding {
	return UTDOAInformationResponseULConfigurationIEBinding{info: t.infoULConfiguration(), codec: ULConfigurationValueCodec{path: "ULConfiguration",
		decode: func(data []byte, options q4.DecodeState) (ULConfiguration, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ULConfiguration
				return empty, err
			}
			var zero UTDOAInformationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(13), raw)
			if err != nil {
				var empty ULConfiguration
				return empty, err
			}
			value, ok := decoded.AsULConfiguration()
			if !ok {
				var empty ULConfiguration
				return empty, q6.Errorf("binding UTDOAInformationResponse-IEs.id-ULConfiguration: no selected value")
			}
			return *value, nil
		},
		encode: func(value ULConfiguration, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationResponseIEValue{id: q5.ProtocolIEID(13), rowULConfiguration: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ULConfiguration, options q4.DecodeState) (ULConfiguration, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaULConfiguration(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ULConfiguration, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaULConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ULConfiguration"
			return sealed
		}(),
	}, inject: func(value ULConfiguration) UTDOAInformationResponseIEValue {
		return UTDOAInformationResponseIEValue{id: q5.ProtocolIEID(13), rowULConfiguration: &value}
	}, get: func(value *UTDOAInformationResponseIEValue) (*ULConfiguration, bool) {
		return value.AsULConfiguration()
	}}
}
func (UTDOAInformationResponseIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: UTDOAInformationResponseIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UTDOAInformationResponseIETable) CriticalityDiagnostics() UTDOAInformationResponseCriticalityDiagnosticsIEBinding {
	return UTDOAInformationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q9.CriticalityDiagnosticsValueCodec {
		sealed := q9.CriticalityDiagnosticsValueCodec{}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			var zero UTDOAInformationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q9.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q9.CriticalityDiagnostics
				return empty, q6.Errorf("binding UTDOAInformationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q9.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q9.CriticalityDiagnostics, options q4.DecodeState) (q9.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q9.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.CriticalityDiagnostics) UTDOAInformationResponseIEValue {
			return UTDOAInformationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *UTDOAInformationResponseIEValue) (*q9.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t UTDOAInformationResponseIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (UTDOAInformationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(13):
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-ULConfiguration requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return UTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		return UTDOAInformationResponseIEField{Id: id, Criticality: criticality, Value: UTDOAInformationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// PosSIBsElemCodec binds the complete source value type.
func PosSIBsElemCodec() PosSIBsElemValueCodec {
	return PosSIBsElemValueCodec{path: "PosSIBsElem", decode: func(data []byte, options q4.DecodeState) (PosSIBsElem, error) {
		var value PosSIBsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PosSIBsElem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value PosSIBsElem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PosSIBsElem, options q4.DecodeState) (PosSIBsElem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPosSIBsElem(&v, &s)
		var root q4.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PosSIBsElem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPosSIBsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBsElem"
		return sealed
	}(),
	}
}

// ULConfigurationCodec binds the complete APER value type.
func ULConfigurationCodec() ULConfigurationValueCodec {
	return UTDOAInformationResponseIEs().ULConfiguration().Codec()
}
func BridgeECIDMeasurementInitiationFailureIETableMethodInfoCause(v ECIDMeasurementInitiationFailureIETable) q5.FieldInfo {
	return v.infoCause()
}
func BridgeECIDMeasurementInitiationFailureIETableMethodInfoCriticalityDiagnostics(v ECIDMeasurementInitiationFailureIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeECIDMeasurementInitiationFailureIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationFailureIETable) q5.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *q5.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *func(*q9.ECIDMeasurementInitiationFailureIEValue) (*q5.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationFailureMeasurementIDIEBinding) *func(q5.MeasurementID) q9.ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeErrorIndicationCauseIEBindingFieldCodec(v *ErrorIndicationCauseIEBinding) *q10.CauseValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCauseIEBindingFieldGet(v *ErrorIndicationCauseIEBinding) *func(*ErrorIndicationIEValue) (*q10.Cause, bool) {
	return &v.get
}
func BridgeErrorIndicationCauseIEBindingFieldInfo(v *ErrorIndicationCauseIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCauseIEBindingFieldInject(v *ErrorIndicationCauseIEBinding) *func(q10.Cause) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldCodec(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *q9.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldGet(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(*ErrorIndicationIEValue) (*q9.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInfo(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInject(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(q9.CriticalityDiagnostics) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationIEFieldFieldReceived(v *ErrorIndicationIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeErrorIndicationIEFieldFieldReplay(v *ErrorIndicationIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEFieldFieldStream(v *ErrorIndicationIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeErrorIndicationIEFieldFieldWithoutReplay(v *ErrorIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEFieldMethodMarshalAPERTo(v *ErrorIndicationIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationIEFieldMethodUnmarshalAPERFrom(v *ErrorIndicationIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationIETableMethodInfoCause(v ErrorIndicationIETable) q5.FieldInfo {
	return v.infoCause()
}
func BridgeErrorIndicationIETableMethodInfoCriticalityDiagnostics(v ErrorIndicationIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeErrorIndicationIEValueFieldId(v *ErrorIndicationIEValue) *q5.ProtocolIEID { return &v.id }
func BridgeErrorIndicationIEValueFieldIsOpaque(v *ErrorIndicationIEValue) *bool      { return &v.isOpaque }
func BridgeErrorIndicationIEValueFieldOpaque(v *ErrorIndicationIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeErrorIndicationIEValueFieldReceived(v *ErrorIndicationIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueFieldReplay(v *ErrorIndicationIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueFieldRowCause(v *ErrorIndicationIEValue) **q10.Cause {
	return &v.rowCause
}
func BridgeErrorIndicationIEValueFieldRowCriticalityDiagnostics(v *ErrorIndicationIEValue) **q9.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeErrorIndicationIEValueFieldWithoutReplay(v *ErrorIndicationIEValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEValueMethodCaptureFraming(v ErrorIndicationIEValue) uint64 {
	return v.captureFraming()
}
func BridgeErrorIndicationIEValueMethodCaptureSemantics(v ErrorIndicationIEValue, a0 q4.SemanticCapture) ErrorIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodCaptureSnapshot(v ErrorIndicationIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeErrorIndicationIEValueMethodCompareSemantics(v ErrorIndicationIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodDecode(v ErrorIndicationIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeErrorIndicationIEValueMethodEncode(v ErrorIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeErrorIndicationIEValueMethodEncodeFresh(v ErrorIndicationIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeErrorIndicationIEValueMethodMatchesID(v ErrorIndicationIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeErrorIndicationIEValueMethodReason(v ErrorIndicationIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeErrorIndicationIEValueMethodRule(v ErrorIndicationIEValue) q4.SourceRule { return v.rule() }
func BridgeOTDOAInformationFailureCauseIEBindingFieldCodec(v *OTDOAInformationFailureCauseIEBinding) *q10.CauseValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldGet(v *OTDOAInformationFailureCauseIEBinding) *func(*OTDOAInformationFailureIEValue) (*q10.Cause, bool) {
	return &v.get
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldInfo(v *OTDOAInformationFailureCauseIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureCauseIEBindingFieldInject(v *OTDOAInformationFailureCauseIEBinding) *func(q10.Cause) OTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *q9.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldGet(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(*OTDOAInformationFailureIEValue) (*q9.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInject(v *OTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(q9.CriticalityDiagnostics) OTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureIEFieldFieldReceived(v *OTDOAInformationFailureIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationFailureIEFieldFieldReplay(v *OTDOAInformationFailureIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureIEFieldFieldStream(v *OTDOAInformationFailureIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v *OTDOAInformationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureIEFieldMethodMarshalAPERTo(v *OTDOAInformationFailureIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationFailureIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationFailureIETableMethodInfoCause(v OTDOAInformationFailureIETable) q5.FieldInfo {
	return v.infoCause()
}
func BridgeOTDOAInformationFailureIETableMethodInfoCriticalityDiagnostics(v OTDOAInformationFailureIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeOTDOAInformationFailureIEValueFieldId(v *OTDOAInformationFailureIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationFailureIEValueFieldIsOpaque(v *OTDOAInformationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationFailureIEValueFieldOpaque(v *OTDOAInformationFailureIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationFailureIEValueFieldReceived(v *OTDOAInformationFailureIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationFailureIEValueFieldReplay(v *OTDOAInformationFailureIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureIEValueFieldRowCause(v *OTDOAInformationFailureIEValue) **q10.Cause {
	return &v.rowCause
}
func BridgeOTDOAInformationFailureIEValueFieldRowCriticalityDiagnostics(v *OTDOAInformationFailureIEValue) **q9.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeOTDOAInformationFailureIEValueFieldWithoutReplay(v *OTDOAInformationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureFraming(v OTDOAInformationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureSemantics(v OTDOAInformationFailureIEValue, a0 q4.SemanticCapture) OTDOAInformationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodCaptureSnapshot(v OTDOAInformationFailureIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationFailureIEValueMethodCompareSemantics(v OTDOAInformationFailureIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodDecode(v OTDOAInformationFailureIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (OTDOAInformationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodEncode(v OTDOAInformationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationFailureIEValueMethodEncodeFresh(v OTDOAInformationFailureIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodMatchesID(v OTDOAInformationFailureIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationFailureIEValueMethodReason(v OTDOAInformationFailureIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationFailureIEValueMethodRule(v OTDOAInformationFailureIEValue) q4.SourceRule {
	return v.rule()
}
func BridgePosSIBsAPERValueFieldContext(v *PosSIBsAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsAPERValueFieldReceived(v *PosSIBsAPERValue) *q4.WireSpan { return &v.received }
func BridgePosSIBsAPERValueFieldReplay(v *PosSIBsAPERValue) *q4.Snapshot   { return &v.replay }
func BridgePosSIBsAPERValueFieldWithoutReplay(v *PosSIBsAPERValue) *bool   { return &v.withoutReplay }
func BridgePosSIBsElemAPERValueFieldContext(v *PosSIBsElemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsElemAPERValueFieldReceived(v *PosSIBsElemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePosSIBsElemAPERValueFieldReplay(v *PosSIBsElemAPERValue) *q4.Snapshot { return &v.replay }
func BridgePosSIBsElemAPERValueFieldWithoutReplay(v *PosSIBsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBsElemFieldExtCount(v *PosSIBsElem) *int64              { return &v.extCount }
func BridgePosSIBsElemFieldExtData(v *PosSIBsElem) *[][]byte            { return &v.extData }
func BridgePosSIBsElemFieldExtOrigin(v *PosSIBsElem) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgePosSIBsElemFieldExtPresent(v *PosSIBsElem) *[]bool           { return &v.extPresent }
func BridgePosSIBsElemFieldExtWire(v *PosSIBsElem) *[]q4.WireSpan       { return &v.extWire }
func BridgePosSIBsElemFieldIEExtensionsIndef(v *PosSIBsElem) *bool      { return &v.iEExtensionsIndef }
func BridgePosSIBsElemFieldPerExtPadding(v *PosSIBsElem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgePosSIBsElemFieldPerPadding(v *PosSIBsElem) *q4.FinalPadding { return &v.perPadding }
func BridgePosSIBsElemFieldPosSIBSegmentsIndef(v *PosSIBsElem) *bool   { return &v.posSIBSegmentsIndef }
func BridgePosSIBsElemFieldReceived(v *PosSIBsElem) *bool              { return &v.received }
func BridgePosSIBsElemFieldReceivedBytes(v *PosSIBsElem) *q4.WireSpan  { return &v.receivedBytes }
func BridgePosSIBsElemFieldReplay(v *PosSIBsElem) *q4.Snapshot         { return &v.replay }
func BridgePosSIBsElemFieldStream(v *PosSIBsElem) *q4.WireSpan         { return &v.stream }
func BridgePosSIBsElemFieldWithoutReplay(v *PosSIBsElem) *bool         { return &v.withoutReplay }
func BridgePosSIBsElemMethodMarshalAPERBudget(v *PosSIBsElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERChanged(v *PosSIBsElem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBsElemMethodMarshalAPERChangedValue(v *PosSIBsElem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBsElemMethodMarshalAPERFreshValue(v *PosSIBsElem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERLegacy(v *PosSIBsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBsElemMethodMarshalAPERPlanned(v *PosSIBsElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBsElemMethodMarshalAPERTo(v *PosSIBsElem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBsElemMethodUnmarshalAPERFrom(v *PosSIBsElem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBsElemMethodUnmarshalAPERLegacy(v *PosSIBsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBsElemMethodUnmarshalAPERWithOptions(v *PosSIBsElem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBsElemValueCodecFieldCapture(v *PosSIBsElemValueCodec) *func(PosSIBsElem, q4.DecodeState) (PosSIBsElem, q4.Snapshot) {
	return &v.capture
}
func BridgePosSIBsElemValueCodecFieldCompare(v *PosSIBsElemValueCodec) *func(PosSIBsElem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePosSIBsElemValueCodecFieldContext(v *PosSIBsElemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsElemValueCodecFieldDecode(v *PosSIBsElemValueCodec) *func([]byte, q4.DecodeState) (PosSIBsElem, error) {
	return &v.decode
}
func BridgePosSIBsElemValueCodecFieldEncode(v *PosSIBsElemValueCodec) *func(PosSIBsElem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBsElemValueCodecFieldPath(v *PosSIBsElemValueCodec) *q4.Path { return &v.path }
func BridgePosSIBsElemValueCodecMethodEncodeBudget(v PosSIBsElemValueCodec, a0 PosSIBsElem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBsElemValueCodecMethodEncodeChanged(v PosSIBsElemValueCodec, a0 PosSIBsElem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBsValueCodecFieldCapture(v *PosSIBsValueCodec) *func(PosSIBs, q4.DecodeState) (PosSIBs, q4.Snapshot) {
	return &v.capture
}
func BridgePosSIBsValueCodecFieldCompare(v *PosSIBsValueCodec) *func(PosSIBs, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePosSIBsValueCodecFieldContext(v *PosSIBsValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBsValueCodecFieldDecode(v *PosSIBsValueCodec) *func([]byte, q4.DecodeState) (PosSIBs, error) {
	return &v.decode
}
func BridgePosSIBsValueCodecFieldEncode(v *PosSIBsValueCodec) *func(PosSIBs, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBsValueCodecFieldPath(v *PosSIBsValueCodec) *q4.Path { return &v.path }
func BridgePosSIBsValueCodecMethodEncodeBudget(v PosSIBsValueCodec, a0 PosSIBs, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBsValueCodecMethodEncodeChanged(v PosSIBsValueCodec, a0 PosSIBs, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULConfigurationAPERValueFieldContext(v *ULConfigurationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeULConfigurationAPERValueFieldReceived(v *ULConfigurationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeULConfigurationAPERValueFieldReplay(v *ULConfigurationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeULConfigurationAPERValueFieldWithoutReplay(v *ULConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeULConfigurationFieldExtCount(v *ULConfiguration) *int64              { return &v.extCount }
func BridgeULConfigurationFieldExtData(v *ULConfiguration) *[][]byte            { return &v.extData }
func BridgeULConfigurationFieldExtOrigin(v *ULConfiguration) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgeULConfigurationFieldExtPresent(v *ULConfiguration) *[]bool           { return &v.extPresent }
func BridgeULConfigurationFieldExtWire(v *ULConfiguration) *[]q4.WireSpan       { return &v.extWire }
func BridgeULConfigurationFieldPerExtPadding(v *ULConfiguration) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeULConfigurationFieldPerPadding(v *ULConfiguration) *q4.FinalPadding { return &v.perPadding }
func BridgeULConfigurationFieldReceived(v *ULConfiguration) *bool              { return &v.received }
func BridgeULConfigurationFieldReceivedBytes(v *ULConfiguration) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeULConfigurationFieldReplay(v *ULConfiguration) *q4.Snapshot { return &v.replay }
func BridgeULConfigurationFieldSrsConfigurationIndef(v *ULConfiguration) *bool {
	return &v.srsConfigurationIndef
}
func BridgeULConfigurationFieldStream(v *ULConfiguration) *q4.WireSpan { return &v.stream }
func BridgeULConfigurationFieldWithoutReplay(v *ULConfiguration) *bool { return &v.withoutReplay }
func BridgeULConfigurationMethodMarshalAPERBudget(v *ULConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERChanged(v *ULConfiguration, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeULConfigurationMethodMarshalAPERChangedValue(v *ULConfiguration, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeULConfigurationMethodMarshalAPERFreshValue(v *ULConfiguration, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERLegacy(v *ULConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeULConfigurationMethodMarshalAPERPlanned(v *ULConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeULConfigurationMethodMarshalAPERTo(v *ULConfiguration, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeULConfigurationMethodUnmarshalAPERFrom(v *ULConfiguration, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeULConfigurationMethodUnmarshalAPERLegacy(v *ULConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeULConfigurationMethodUnmarshalAPERWithOptions(v *ULConfiguration, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeULConfigurationValueCodecFieldCapture(v *ULConfigurationValueCodec) *func(ULConfiguration, q4.DecodeState) (ULConfiguration, q4.Snapshot) {
	return &v.capture
}
func BridgeULConfigurationValueCodecFieldCompare(v *ULConfigurationValueCodec) *func(ULConfiguration, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeULConfigurationValueCodecFieldContext(v *ULConfigurationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeULConfigurationValueCodecFieldDecode(v *ULConfigurationValueCodec) *func([]byte, q4.DecodeState) (ULConfiguration, error) {
	return &v.decode
}
func BridgeULConfigurationValueCodecFieldEncode(v *ULConfigurationValueCodec) *func(ULConfiguration, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULConfigurationValueCodecFieldPath(v *ULConfigurationValueCodec) *q4.Path { return &v.path }
func BridgeULConfigurationValueCodecMethodEncodeBudget(v ULConfigurationValueCodec, a0 ULConfiguration, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeULConfigurationValueCodecMethodEncodeChanged(v ULConfigurationValueCodec, a0 ULConfiguration, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldCodec(v *UTDOAInformationFailureCauseIEBinding) *q10.CauseValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldGet(v *UTDOAInformationFailureCauseIEBinding) *func(*UTDOAInformationFailureIEValue) (*q10.Cause, bool) {
	return &v.get
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldInfo(v *UTDOAInformationFailureCauseIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureCauseIEBindingFieldInject(v *UTDOAInformationFailureCauseIEBinding) *func(q10.Cause) UTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *q9.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldGet(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(*UTDOAInformationFailureIEValue) (*q9.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureCriticalityDiagnosticsIEBindingFieldInject(v *UTDOAInformationFailureCriticalityDiagnosticsIEBinding) *func(q9.CriticalityDiagnostics) UTDOAInformationFailureIEValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureIEFieldFieldReceived(v *UTDOAInformationFailureIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationFailureIEFieldFieldReplay(v *UTDOAInformationFailureIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureIEFieldFieldStream(v *UTDOAInformationFailureIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v *UTDOAInformationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureIEFieldMethodMarshalAPERTo(v *UTDOAInformationFailureIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationFailureIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationFailureIETableMethodInfoCause(v UTDOAInformationFailureIETable) q5.FieldInfo {
	return v.infoCause()
}
func BridgeUTDOAInformationFailureIETableMethodInfoCriticalityDiagnostics(v UTDOAInformationFailureIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUTDOAInformationFailureIEValueFieldId(v *UTDOAInformationFailureIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationFailureIEValueFieldIsOpaque(v *UTDOAInformationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationFailureIEValueFieldOpaque(v *UTDOAInformationFailureIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationFailureIEValueFieldReceived(v *UTDOAInformationFailureIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationFailureIEValueFieldReplay(v *UTDOAInformationFailureIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureIEValueFieldRowCause(v *UTDOAInformationFailureIEValue) **q10.Cause {
	return &v.rowCause
}
func BridgeUTDOAInformationFailureIEValueFieldRowCriticalityDiagnostics(v *UTDOAInformationFailureIEValue) **q9.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUTDOAInformationFailureIEValueFieldWithoutReplay(v *UTDOAInformationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureFraming(v UTDOAInformationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureSemantics(v UTDOAInformationFailureIEValue, a0 q4.SemanticCapture) UTDOAInformationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodCaptureSnapshot(v UTDOAInformationFailureIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationFailureIEValueMethodCompareSemantics(v UTDOAInformationFailureIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodDecode(v UTDOAInformationFailureIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (UTDOAInformationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodEncode(v UTDOAInformationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationFailureIEValueMethodEncodeFresh(v UTDOAInformationFailureIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodMatchesID(v UTDOAInformationFailureIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationFailureIEValueMethodReason(v UTDOAInformationFailureIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationFailureIEValueMethodRule(v UTDOAInformationFailureIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *q9.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldGet(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(*UTDOAInformationResponseIEValue) (*q9.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInject(v *UTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(q9.CriticalityDiagnostics) UTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeUTDOAInformationResponseIEFieldFieldReceived(v *UTDOAInformationResponseIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationResponseIEFieldFieldReplay(v *UTDOAInformationResponseIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseIEFieldFieldStream(v *UTDOAInformationResponseIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v *UTDOAInformationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseIEFieldMethodMarshalAPERTo(v *UTDOAInformationResponseIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationResponseIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationResponseIETableMethodInfoCriticalityDiagnostics(v UTDOAInformationResponseIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUTDOAInformationResponseIETableMethodInfoULConfiguration(v UTDOAInformationResponseIETable) q5.FieldInfo {
	return v.infoULConfiguration()
}
func BridgeUTDOAInformationResponseIEValueFieldId(v *UTDOAInformationResponseIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationResponseIEValueFieldIsOpaque(v *UTDOAInformationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationResponseIEValueFieldOpaque(v *UTDOAInformationResponseIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationResponseIEValueFieldReceived(v *UTDOAInformationResponseIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationResponseIEValueFieldReplay(v *UTDOAInformationResponseIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseIEValueFieldRowCriticalityDiagnostics(v *UTDOAInformationResponseIEValue) **q9.CriticalityDiagnostics {
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
func BridgeUTDOAInformationResponseIEValueMethodCaptureSemantics(v UTDOAInformationResponseIEValue, a0 q4.SemanticCapture) UTDOAInformationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodCaptureSnapshot(v UTDOAInformationResponseIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationResponseIEValueMethodCompareSemantics(v UTDOAInformationResponseIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodDecode(v UTDOAInformationResponseIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (UTDOAInformationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodEncode(v UTDOAInformationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationResponseIEValueMethodEncodeFresh(v UTDOAInformationResponseIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodMatchesID(v UTDOAInformationResponseIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationResponseIEValueMethodReason(v UTDOAInformationResponseIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationResponseIEValueMethodRule(v UTDOAInformationResponseIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldCodec(v *UTDOAInformationResponseULConfigurationIEBinding) *ULConfigurationValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldGet(v *UTDOAInformationResponseULConfigurationIEBinding) *func(*UTDOAInformationResponseIEValue) (*ULConfiguration, bool) {
	return &v.get
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldInfo(v *UTDOAInformationResponseULConfigurationIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseULConfigurationIEBindingFieldInject(v *UTDOAInformationResponseULConfigurationIEBinding) *func(ULConfiguration) UTDOAInformationResponseIEValue {
	return &v.inject
}
